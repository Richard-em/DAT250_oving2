"""Provides the configuration for the Social Insecurity application.

This file is used to set the configuration for the application.

Example:
    from flask import Flask
    from social_insecurity.config import Config

    app = Flask(__name__)
    app.config.from_object(Config)

    # Use the configuration
    secret_key = app.config["SECRET_KEY"]
"""

import os
from pathlib import Path


class Config:
    # TODO: Use this with wtforms
    SECRET_KEY = os.environ.get("SECRET_KEY") or "secret"

    # Added checks for characters enabling path traversal, in case of tampering.
    _db_env = os.environ.get("SQLITE3_DATABASE_PATH", "sqlite3.db").strip()
    if os.path.isabs(_db_env) or ".." in Path(_db_env).parts or "/" in _db_env or "\\" in _db_env:
        raise ValueError(f"Unsafe SQLITE3_DATABASE_PATH: {_db_env}")
    SQLITE3_DATABASE_PATH = _db_env

    # Added checks for characters enabling path traversal, in case of tampering.
    # Use environment variable, but sanitize the value
    _uploads_env = os.environ.get("UPLOADS_FOLDER_PATH", "uploads").strip()
    if os.path.isabs(_uploads_env) or ".." in Path(_uploads_env).parts or "/" in _uploads_env or "\\" in _uploads_env:
        raise ValueError(f"Unsafe UPLOADS_FOLDER_PATH: {_uploads_env}")
    UPLOADS_FOLDER_PATH = _uploads_env

    ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp"}

    # Added a limit to filesize (10 MB)
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024

    # TODO: I should probably implement this wtforms feature, but it's not a priority
    WTF_CSRF_ENABLED = False


# Added checks to ensure uploads path is relative, and within the instance. Also using .resolve()
def create_uploads_folder(app) -> None:
    """
    Safely create the uploads folder inside the instance directory.

    Prevents absolute paths or directory traversal in configuration.
    """
    uploads_rel = str(app.config.get("UPLOADS_FOLDER_PATH", "uploads"))
    if Path(uploads_rel).is_absolute():
        raise ValueError("UPLOADS_FOLDER_PATH must be relative")

    upload_dir = (Path(app.instance_path) / uploads_rel).resolve()

    if not str(upload_dir).startswith(str(Path(app.instance_path).resolve())):
        raise ValueError("Uploads path escapes instance_path")

    upload_dir.mkdir(parents=True, exist_ok=True)
