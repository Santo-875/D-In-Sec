"""
D-In-Sec Mock Site — Flask Application
Corporate Document Verification Portal (Module 1)

A clean, standard enterprise web application that handles user
authentication, PII data collection, and document uploads.
Completely oblivious to DPDP/CERT-In compliance — that's the
downstream sidecar's job.

All significant actions are logged with RAW, un-anonymized PII
to both stdout and logs/system.log.
"""

import os
import json
import logging
from dotenv import load_dotenv

# Load .env from the root of the project
env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
load_dotenv(dotenv_path=env_path)
from logging.handlers import RotatingFileHandler
from flask import Flask, redirect, url_for
from flask_login import LoginManager
from models import db, User
from routes import register_blueprints


def create_app():
    """Application factory."""
    app = Flask(__name__)

    # ── Configuration ───────────────────────────────────────────
    base_dir = os.path.abspath(os.path.dirname(__file__))

    app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'
    app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(base_dir, 'instance', 'mock_site.db')}"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = os.path.join(base_dir, 'uploads')
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload

    # ── Database Init ───────────────────────────────────────────
    os.makedirs(os.path.join(base_dir, 'instance'), exist_ok=True)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    db.init_app(app)

    with app.app_context():
        db.create_all()

    # ── Flask-Login ─────────────────────────────────────────────
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # ── Logging Setup ───────────────────────────────────────────
    setup_logging(app, base_dir)

    # ── Register Blueprints ─────────────────────────────────────
    register_blueprints(app)

    # Jinja2 custom filter: parse JSON string in templates
    import json as _json
    app.jinja_env.filters['from_json'] = lambda s: _json.loads(s) if s else []

    # ── Root redirect ───────────────────────────────────────────
    @app.route('/')
    def root():
        return redirect(url_for('auth.login'))

    return app


def setup_logging(app, base_dir):
    """
    Configure application logging.
    Logs are written to BOTH stdout and logs/system.log
    with raw, un-anonymized PII — the pivot point for the
    downstream compliance sidecar.
    """
    log_dir = os.path.join(base_dir, 'logs')
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, 'system.log')

    # Log format matching the spec
    log_format = '[%(asctime)s] [%(levelname)s] %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'

    formatter = logging.Formatter(log_format, datefmt=date_format)

    # File handler (rotating, 5 MB max, 3 backups)
    file_handler = RotatingFileHandler(
        log_file, maxBytes=5 * 1024 * 1024, backupCount=3
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.DEBUG)

    # Application logger
    logger = logging.getLogger('mock_site')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    # Also capture Flask/Werkzeug logs
    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)


if __name__ == '__main__':
    application = create_app()
    _debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    _host = os.environ.get("FLASK_HOST", "127.0.0.1")
    _port = int(os.environ.get("PORT", "5000"))
    print("\n" + "=" * 60)
    print("  D-In-Sec Mock Corporate Portal")
    print("  Module 1 — Document Verification System")
    print(f"  Server running on http://{_host}:{_port}")
    print("=" * 60 + "\n")
    application.run(debug=_debug, host=_host, port=_port)
