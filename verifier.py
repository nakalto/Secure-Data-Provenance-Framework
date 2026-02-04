from dataclasses import dataclass
from typing import Optional

from provenance_engine import (
    append_provenance_event,
    get_case,
    get_latest_case_by_filename,
    get_latest_file_version,
    validate_case_chain,
)
from utils.crypto_utils import sha256_file


@dataclass(frozen=True)
class VerificationResult:
    status: str  # VALID | TAMPERED_FILE | TAMPERED_CHAIN | TAMPERED_HMAC | MISSING_HISTORY
    reason: str
    expected_sha256: Optional[str] = None
    observed_sha256: Optional[str] = None
    case_id: Optional[int] = None


def verify_file_against_provenance(
    *,
    file_path: str,
    filename: str,
    case_id: Optional[int],
    request_id: str,
    client_ip: Optional[str],
    user_agent: Optional[str],
) -> VerificationResult:
    observed = sha256_file(file_path)

    resolved_case_id: Optional[int] = None
    if case_id is not None:
        case = get_case(int(case_id))
        if case is None:
            return VerificationResult(
                status="MISSING_HISTORY",
                reason="Provided case_id does not exist",
                expected_sha256=None,
                observed_sha256=observed,
                case_id=None,
            )
        resolved_case_id = int(case["id"])
    else:
        case = get_latest_case_by_filename(filename)
        if case is None:
            return VerificationResult(
                status="MISSING_HISTORY",
                reason="No case exists for this filename",
                expected_sha256=None,
                observed_sha256=observed,
                case_id=None,
            )
        resolved_case_id = int(case["id"])

    chain = validate_case_chain(resolved_case_id)
    if not chain.ok:
        status = "TAMPERED_CHAIN" if chain.failure_type == "CHAIN" else "TAMPERED_HMAC"
        return VerificationResult(
            status=status,
            reason=f"Provenance chain validation failed: {chain.error}",
            expected_sha256=None,
            observed_sha256=observed,
            case_id=resolved_case_id,
        )

    latest_version = get_latest_file_version(resolved_case_id)
    if latest_version is None:
        return VerificationResult(
            status="MISSING_HISTORY",
            reason="No file versions exist for this case",
            expected_sha256=None,
            observed_sha256=observed,
            case_id=resolved_case_id,
        )

    expected = latest_version["file_hash"]

    # Record verification attempt as an append-only audit event.
    append_provenance_event(
        case_id=resolved_case_id,
        file_version_id=None,
        action="VERIFY",
        file_hash=observed,
        request_id=request_id,
        client_ip=client_ip,
        user_agent=user_agent,
    )

    if observed == expected:
        return VerificationResult(
            status="VALID",
            reason="File hash matches the latest stored file version",
            expected_sha256=expected,
            observed_sha256=observed,
            case_id=resolved_case_id,
        )

    return VerificationResult(
        status="TAMPERED_FILE",
        reason="File hash does NOT match the latest stored file version",
        expected_sha256=expected,
        observed_sha256=observed,
        case_id=resolved_case_id,
    )
