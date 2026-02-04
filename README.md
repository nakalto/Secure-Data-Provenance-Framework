# Designing a Secure Data Provenance Framework for Ensuring Information Integrity

## Overview
This project implements a **secure, append-only data provenance framework** suitable for cybersecurity and digital forensics use-cases.
It records **who/when/what** for files uploaded through a local Flask web interface and provides **tamper detection** for:
- The **file contents** (via SHA-256 hashing)
- The **provenance database records** (via hash chaining + HMAC)

The system is designed to be defendable in an academic viva: it uses standard cryptographic primitives (SHA-256, HMAC-SHA256), provides clear integrity logic on the backend, and exposes a minimal web UI for demonstration.

## Architecture (High-Level)
- `app.py`
  - Flask web application.
  - Handles file upload and verification requests.
- `db.py`
  - SQLite connection + schema initialization.
- `utils/crypto_utils.py`
  - SHA-256 hashing for bytes/files.
  - Canonical JSON serialization.
  - HMAC signing helper.
- `utils/file_utils.py`
  - Safe filename handling.
  - Unique on-disk storage naming to prevent overwrites.
- `provenance_engine.py`
  - SQLite-backed `files` + `provenance` tables.
  - Append-only provenance records with per-file hash chaining.
  - HMAC-signed provenance records.
  - Full chain integrity verification for a file.
- `verifier.py`
  - Verifies re-uploaded file hashes against latest provenance record.
  - Appends a `VERIFY` provenance record for each verification attempt.

### Data Storage
- `data/provenance.db`: SQLite database storing files and provenance records.
- `data/hmac_secret.key`: auto-generated 32-byte secret key (created on first run).
- `data/system_id.txt`: backend-generated stable system identity.
- `data/uploads/`: stores uploaded files (for demo).

## Database Schema

### `files` table
- `id` (PRIMARY KEY)
- `filename`
- `stored_path`
- `original_hash`
- `upload_time`
- `system_id`

### `provenance` table
- `id` (PRIMARY KEY)
- `file_id` (FOREIGN KEY → files.id)
- `action` (`CREATE` or `VERIFY`)
- `file_hash` (SHA-256)
- `prev_hash` (previous provenance hash for this file)
- `curr_hash` (current provenance hash)
- `timestamp` (UTC ISO8601)
- `system_id` (backend identity)
- `record_hmac` (HMAC-SHA256 over `curr_hash`)

## Provenance Record Format
Each provenance record contains:
- `id`: unique record ID
- `file_id`: file foreign key
- `action`: `CREATE` or `VERIFY`
- `timestamp`: UTC ISO8601
- `file_hash`: SHA-256 of the file contents
- `prev_hash`: previous record’s provenance hash (or `GENESIS` for the first record for that file)
- `curr_hash`: SHA-256 of canonical JSON of core fields
- `system_id`: backend-generated identity
- `record_hmac`: HMAC-SHA256(secret_key, curr_hash)

## Core Algorithms (Pseudocode)

### A) Provenance Generation + Hash Chaining
```
INPUT: uploaded_file
file_sha256 = SHA256(uploaded_file_bytes)
prev = last_record.curr_hash if exists else "GENESIS"
record_core = {
  file_id, action, file_hash=file_sha256, prev_hash=prev, timestamp_utc, system_id
}
prov_hash = SHA256(canonical_json(record_core))
record_hmac = HMAC_SHA256(secret_key, prov_hash)
INSERT {record_core + curr_hash=prov_hash + record_hmac} into SQLite provenance table
```

### B) Provenance Log Integrity Verification
```
prev = "GENESIS"
FOR each record for a given file_id (in order):
  ASSERT record.prev_hash == prev
  expected_hash = SHA256(canonical_json(record_core_fields))
  ASSERT record.curr_hash == expected_hash
  ASSERT record.record_hmac == HMAC_SHA256(secret_key, record.curr_hash)
  prev = record.curr_hash
RETURN OK if all checks pass
```

### C) File Verification
```
observed = SHA256(reuploaded_file_bytes)
file_id = latest file row where files.filename == uploaded_filename
IF file_id missing: return UNKNOWN
VERIFY the provenance chain for file_id (hash chain + HMAC)
IF chain invalid: return TAMPERED_DB
latest = latest provenance record for file_id
APPEND a VERIFY record with file_hash=observed (audit event)
IF observed == latest.file_hash: return VALID
ELSE: return TAMPERED_FILE
```

## How to Run (Linux)
### 1) Create venv and install deps
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2) Start the web server
```bash
python app.py
```
Open: `http://127.0.0.1:5000`

## Logs (Forensic Audit Trail)
- The application writes structured logs to: `data/app.log`
- Each request gets a backend-generated **request_id** (correlation ID) included in every log line.

Example log line:
```
2026-01-21 19:10:01,123Z INFO request_id=... upload_success case_id=12 filename=doc.pdf version=1 bytes=12345
```

## Run Tests
This project includes a small `pytest` suite for academic validation.

```bash
pytest -q
```

The tests run against an isolated temporary database and key directory by setting:
- `PROV_DB_PATH` (temporary SQLite path)
- `PROV_DATA_DIR` (temporary directory for `hmac_secret.key` and `system_id.txt`)

## Demo Steps
- Upload a file on the home page.
- Note the displayed SHA-256 and provenance hashes, plus the generated Case ID.
- Re-upload the same file at `/verify`:
  - You should see **VALID**.
- Modify the file locally (even a single byte) and re-upload at `/verify`:
  - You should see **TAMPERED (FILE MODIFIED)**.
- Visit `/history/<case_id>` to see the append-only timeline (CREATE + VERIFY actions).
- If you manually edit the SQLite DB (`data/provenance.db`) to change hashes:
  - Verification will show **TAMPERED (PROVENANCE CHAIN INVALID)**.

## Security Notes (Design Decisions)
- **SHA-256** provides strong collision resistance for integrity checks.
- **Hash chaining** makes the log append-only in a cryptographic sense: changing an older record breaks all subsequent links.
- **HMAC** prevents an attacker from forging valid-looking records without the secret key.
- **Canonical JSON** avoids hash changes due to formatting/key order.
- **Backend-only enforcement**: verification and record creation are server-side; the UI only submits files.
- **Advisory file locking** reduces corruption risk under concurrent requests.

## Limitations
- No authentication/authorization (intentionally omitted per requirements).
- Local storage only; a privileged attacker with filesystem access could delete the entire log (availability attack).
- Using filename-based lookup is simple but not perfect for real-world multi-version tracking.

## Future Enhancements
- Enable SQLite WAL mode and periodic signed snapshots for stronger auditability.
- Add per-file immutable identifiers and multi-version support.
- Integrate digital signatures (Ed25519) and trusted timestamping.
- Export signed audit reports for forensic chain-of-custody.
