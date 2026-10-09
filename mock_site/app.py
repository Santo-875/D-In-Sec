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
import hmac
import logging
import secrets
from dotenv import load_dotenv

# Load .env from the root of the project
env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
load_dotenv(dotenv_path=env_path)
import threading
import time
from logging.handlers import RotatingFileHandler
from flask import Flask, redirect, url_for, request, session, abort
from flask_login import LoginManager
from models import db, User
from routes import register_blueprints


def create_app(config_override=None):
    """Application factory."""
    app = Flask(__name__)

    # ── Configuration ───────────────────────────────────────────
    base_dir = os.path.abspath(os.path.dirname(__file__))

    secret_key = os.environ.get('FLASK_SECRET_KEY')
    generated_secret = not secret_key
    if generated_secret:
        # Random per-process key: sessions are invalidated on every restart.
        secret_key = secrets.token_hex(32)
    app.config['SECRET_KEY'] = secret_key
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(base_dir, 'instance', 'mock_site.db')}"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = os.path.join(base_dir, 'uploads')
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload

    if config_override:
        app.config.update(config_override)

    # ── Database Init ───────────────────────────────────────────
    os.makedirs(os.path.join(base_dir, 'instance'), exist_ok=True)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    db.init_app(app)

    with app.app_context():
        db.create_all()
        from sqlalchemy import text
        try:
            cols = [row[1] for row in db.session.execute(text("PRAGMA table_info(documents)")).fetchall()]
            if 'file_sha256' not in cols:
                db.session.execute(text("ALTER TABLE documents ADD COLUMN file_sha256 VARCHAR(64)"))
                db.session.commit()
            if 'm3_synced' not in cols:
                db.session.execute(text("ALTER TABLE documents ADD COLUMN m3_synced BOOLEAN DEFAULT 0"))
                db.session.commit()
        except Exception as e:
            db.session.rollback()
            logging.getLogger('mock_site').warning(f"Error checking/migrating documents table: {e}")

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
    if generated_secret:
        logging.getLogger('mock_site').warning(
            "event=CONFIG_WARNING FLASK_SECRET_KEY not set; using a random "
            "per-process key (sessions will not survive a restart)."
        )

    # ── CSRF protection (session token, no extra dependency) ────
    def csrf_token():
        token = session.get('_csrf_token')
        if not token:
            token = secrets.token_urlsafe(32)
            session['_csrf_token'] = token
        return token

    app.jinja_env.globals['csrf_token'] = csrf_token

    @app.before_request
    def csrf_protect():
        if request.method != 'POST' or not app.config.get('WTF_CSRF_ENABLED', True):
            return None
        sent = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token', '')
        expected = session.get('_csrf_token', '')
        if not sent or not expected or not hmac.compare_digest(sent, expected):
            logging.getLogger('mock_site').warning(
                f"event=CSRF_REJECTED path={request.path}"
            )
            abort(400, description='CSRF token missing or invalid.')
        return None

    # ── Register Blueprints ─────────────────────────────────────
    register_blueprints(app)

    # Jinja2 custom filter: parse JSON string in templates
    import json as _json
    app.jinja_env.filters['from_json'] = lambda s: _json.loads(s) if s else []

    # ── Root redirect & login alias ─────────────────────────────
    @app.route('/')
    def root():
        return redirect(url_for('auth.login'))

    @app.route('/login', methods=['GET', 'POST'])
    def login_alias():
        from routes.auth import login as auth_login
        return auth_login()

    app.retry_unsynced_documents = retry_unsynced_documents

    if not app.config.get('TESTING'):
        def _retry_daemon():
            while True:
                time.sleep(15)
                try:
                    with app.app_context():
                        retry_unsynced_documents(limit=10)
                except Exception as ex:
                    logging.getLogger('mock_site').debug(f"M3 retry worker exception: {ex}")

        t = threading.Thread(target=_retry_daemon, daemon=True)
        t.start()

    return app


def retry_unsynced_documents(limit: int = 10) -> int:
    """
    Retries up to `limit` unsynced documents: re-pushes leaf doc_<id>
    (recomputed masked hash from doc_type:file_name, real hash = file_sha256).
    Sets m3_synced = True on success.
    Returns count of successfully synced documents.
    """
    import hashlib
    from models import Document
    from m3_client import push_leaf
    unsynced = Document.query.filter_by(m3_synced=False).order_by(Document.id.asc()).limit(limit).all()
    synced_count = 0
    for doc in unsynced:
        if not doc.file_sha256:
            continue
        masked_pii_hash = hashlib.sha256(f"{doc.doc_type}:{doc.file_name}".encode("utf-8")).hexdigest()
        real_data_hash = doc.file_sha256
        if push_leaf(f"user_{doc.user_id}", f"doc_{doc.id}", masked_pii_hash, real_data_hash):
            doc.m3_synced = True
            db.session.commit()
            synced_count += 1
    return synced_count


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
