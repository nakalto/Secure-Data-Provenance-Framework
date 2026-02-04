import os
import secrets
import logging

from flask import Flask, g, has_request_context, render_template, request

from provenance_engine import list_recent_cases, register_upload_as_new_version
from utils.crypto_utils import sha256_file
from utils.file_utils import save_upload
from verifier import verify_file_against_provenance


BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(BASE_DIR, "data")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")


class _RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if has_request_context():
            record.request_id = getattr(g, "request_id", "-")
        else:
            record.request_id = "-"
        return True


def _configure_logging(app: Flask) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    log_path = os.path.join(DATA_DIR, "app.log")

    logger = logging.getLogger("provenance")
    logger.setLevel(logging.INFO)

    if not any(isinstance(h, logging.FileHandler) and h.baseFilename == log_path for h in logger.handlers):
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fmt = logging.Formatter(
            "%(asctime)sZ %(levelname)s request_id=%(request_id)s %(message)s"
        )
        fh.setFormatter(fmt)
        fh.addFilter(_RequestIdFilter())
        logger.addHandler(fh)

    app.logger.handlers = logger.handlers
    app.logger.setLevel(logger.level)


def create_app() -> Flask:
    app = Flask(__name__)

    _configure_logging(app)

    # Backend-enforced limits (avoid memory/disk abuse).
    app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB

    os.makedirs(UPLOAD_DIR, exist_ok=True)

    @app.before_request
    def _attach_request_context():
        # Request correlation ID for audit trails and logs.
        g.request_id = secrets.token_hex(16)

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/recent")
    def recent():
        cases = list_recent_cases(limit=10)
        app.logger.info("recent_list size=%s", len(cases))
        return render_template("recent.html", cases=cases)

    @app.post("/upload")
    def upload():
        if "file" not in request.files:
            return render_template("result.html", error="No file part in request")

        f = request.files["file"]
        if not f or f.filename is None or f.filename.strip() == "":
            return render_template("result.html", error="No file selected")

        try:
            filename, stored_path = save_upload(f, UPLOAD_DIR)
        except ValueError as e:
            return render_template("result.html", error=str(e))

        file_hash = sha256_file(stored_path)

        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        user_agent = request.headers.get("User-Agent")

        try:
            reg = register_upload_as_new_version(
                filename=filename,
                stored_path=stored_path,
                file_hash=file_hash,
                request_id=g.request_id,
                client_ip=client_ip,
                user_agent=user_agent,
            )
        except ValueError as e:
            return render_template(
                "result.html",
                error=str(e),
                filename=filename,
                file_sha256=file_hash,
            )

        app.logger.info(
            "upload_success case_id=%s filename=%s version=%s bytes=%s",
            reg["case"]["id"],
            filename,
            reg["version"]["version"],
            reg["version"]["file_size"],
        )

        return render_template(
            "result.html",
            filename=filename,
            file_sha256=file_hash,
            case=reg["case"],
            version=reg["version"],
            record=reg["event"],
            case_id=int(reg["case"]["id"]),
        )

    @app.get("/verify")
    def verify_page():
        return render_template("verify.html")

    @app.post("/verify")
    def verify_action():
        if "file" not in request.files:
            return render_template("verify.html", error="No file part in request")

        f = request.files["file"]
        if not f or f.filename is None or f.filename.strip() == "":
            return render_template("verify.html", error="No file selected")

        try:
            filename, tmp_path = save_upload(f, UPLOAD_DIR)
        except ValueError as e:
            return render_template("verify.html", error=str(e))

        raw_case_id = request.form.get("case_id")
        case_id = int(raw_case_id) if raw_case_id and raw_case_id.isdigit() else None

        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        user_agent = request.headers.get("User-Agent")

        try:
            try:
                result = verify_file_against_provenance(
                    file_path=tmp_path,
                    filename=filename,
                    case_id=case_id,
                    request_id=g.request_id,
                    client_ip=client_ip,
                    user_agent=user_agent,
                )
            except ValueError as e:
                return render_template(
                    "verify.html",
                    filename=filename,
                    error=str(e),
                )
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

        app.logger.info(
            "verify_result status=%s case_id=%s filename=%s",
            result.status,
            result.case_id,
            filename,
        )

        return render_template(
            "verify.html",
            filename=filename,
            result=result,
            case_id=result.case_id,
        )

    @app.get("/history/<int:case_id>")
    def history(case_id: int):
        from provenance_engine import get_case, list_provenance_events, validate_case_chain

        case = get_case(case_id)
        if case is None:
            return render_template("history.html", error="Case not found")

        chain = validate_case_chain(case_id)
        records = list_provenance_events(case_id)
        app.logger.info(
            "history_view case_id=%s chain_ok=%s records=%s",
            case_id,
            chain.ok,
            len(records),
        )
        return render_template(
            "history.html",
            case=case,
            chain=chain,
            records=records,
        )

    @app.get("/history")
    def history_search():
        from flask import redirect

        raw_case_id = request.args.get("case_id")
        if raw_case_id:
            if raw_case_id.isdigit():
                return redirect(f"/history/{int(raw_case_id)}")
            cases = list_recent_cases(limit=10)
            return render_template(
                "history_search.html",
                cases=cases,
                error="case_id must be a number",
                case_id=raw_case_id,
            )

        cases = list_recent_cases(limit=10)
        return render_template("history_search.html", cases=cases, case_id=None)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=False)
