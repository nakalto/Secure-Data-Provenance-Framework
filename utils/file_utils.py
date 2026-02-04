import os
import secrets
from typing import Tuple

from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def save_upload(file_obj: FileStorage, upload_dir: str) -> Tuple[str, str]:
    ensure_dir(upload_dir)

    original_name = file_obj.filename or ""
    safe_name = secure_filename(original_name)
    if safe_name == "":
        raise ValueError("Invalid filename")

    token = secrets.token_hex(8)
    stored_name = f"{token}__{safe_name}"
    stored_path = os.path.join(upload_dir, stored_name)

    file_obj.save(stored_path)
    return safe_name, stored_path
