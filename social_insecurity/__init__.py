"""Provides the social_insecurity package for the Social Insecurity application.

The package contains the Flask application factory.
"""

from pathlib import Path
from shutil import rmtree
from typing import cast

from flask import Flask, current_app
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect

from social_insecurity.config import Config
from social_insecurity.database import SQLite3

sqlite = SQLite3()
login = LoginManager()
bcrypt = Bcrypt()
csrf = CSRFProtect()

def create_app(test_config=None) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.from_object(test_config)

    sqlite.init_app(app, schema="schema.sql")
    login.init_app(app)
    bcrypt.init_app(app)
    csrf.init_app(app)
    login.login_view = "index"

    with app.app_context():
        create_uploads_folder(app)

    @app.cli.command("reset")
    def reset_command() -> None:
        """Reset the app."""
        instance_path = Path(current_app.instance_path)
        if instance_path.exists():
            rmtree(instance_path)

    with app.app_context():
        from social_insecurity.routes import register_routes
        register_routes(app)

    return app


# Changed function below to protect against potential changes to UPLOADS_FOLDER_PATH
# Keeps folder in flask instance, .resolve() for paths, prevent overwriting files with folders
def create_uploads_folder(app: Flask) -> None:
    """Safely ensure the instance and uploads folders exist."""
    instance_path = Path(app.instance_path)
    uploads_rel = cast(str, app.config["UPLOADS_FOLDER_PATH"])
    upload_path = instance_path / uploads_rel

    # Ensure the uploads path is inside the instance directory
    try:
        upload_path.resolve(strict=False).relative_to(
            instance_path.resolve(strict=True))
    except Exception:
        raise ValueError(f"Unsafe UPLOADS_FOLDER_PATH: {uploads_rel}")

    if upload_path.exists() and not upload_path.is_dir():
        raise RuntimeError(
            f"Expected uploads folder, but found a file at {upload_path}")

    upload_path.mkdir(parents=True, exist_ok=True)
