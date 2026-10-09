"""
D-In-Sec Mock Site — Database Models

SECURITY NOTE:
  Raw PII is NOT stored here. All PII lives encrypted in vault.db.
  This DB holds only tokens, metadata, and structural records.
"""

from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):
    """User account — stores credentials and vault token reference only."""
    __tablename__ = 'users'

    id            = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username      = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email         = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin      = db.Column(db.Boolean, default=False, nullable=False)
    active        = db.Column(db.Boolean, default=True, nullable=False)

    # Vault token — points to encrypted PII blob in vault.db
    profile_token = db.Column(db.String(64), nullable=True)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    documents     = db.relationship('Document', backref='owner', lazy=True,
                                    foreign_keys='Document.user_id',
                                    cascade='all, delete-orphan')
    dsar_requests = db.relationship('DsarRequest', backref='user', lazy=True,
                                    foreign_keys='DsarRequest.user_id',
                                    cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Flask-Login uses is_active property; map it to our 'active' column
    @property
    def is_active(self):
        return self.active

    @is_active.setter
    def is_active(self, value):
        self.active = value

    def __repr__(self):
        return f'<User {self.username} admin={self.is_admin}>'


class Document(db.Model):
    """Uploaded document — file_token points to encrypted file in vault.db."""
    __tablename__ = 'documents'

    id           = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    doc_type     = db.Column(db.String(50), nullable=False)
    file_token   = db.Column(db.String(64), nullable=False)
    file_name    = db.Column(db.String(255), nullable=True, default='')
    file_path    = db.Column(db.String(500), nullable=True, default='')
    s3_key       = db.Column(db.String(500), nullable=True, default='')
    file_sha256  = db.Column(db.String(64), nullable=True)
    m3_synced    = db.Column(db.Boolean, default=False)
    status       = db.Column(db.String(20), default='Pending')   # Pending/Verified/Rejected
    admin_note   = db.Column(db.Text, nullable=True)
    submitted_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    verified_at  = db.Column(db.DateTime, nullable=True)
    verified_by  = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    def __repr__(self):
        return f'<Document [{self.doc_type}] [{self.status}]>'


class FieldSchema(db.Model):
    """Admin-defined dynamic PII field definitions."""
    __tablename__ = 'field_schemas'

    id            = db.Column(db.Integer, primary_key=True, autoincrement=True)
    field_name    = db.Column(db.String(80), unique=True, nullable=False)
    field_label   = db.Column(db.String(120), nullable=False)
    field_type    = db.Column(db.String(30), nullable=False, default='text')
    regex_pattern = db.Column(db.String(512), nullable=True)
    mask_label    = db.Column(db.String(80), nullable=True)
    pii_category  = db.Column(db.String(50), nullable=True)
    is_required   = db.Column(db.Boolean, default=False)
    placeholder   = db.Column(db.String(200), nullable=True)
    help_text     = db.Column(db.String(300), nullable=True)
    sort_order    = db.Column(db.Integer, default=0)
    created_at    = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<FieldSchema {self.field_name}>'


class DsarRequest(db.Model):
    """DPDP Data Subject Access / Erasure Requests."""
    __tablename__ = 'dsar_requests'

    id           = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    request_type = db.Column(db.String(20), nullable=False)   # ACCESS or ERASURE
    # Statuses: pending → approved (admin ok'd) → fields_selected (user chose) → completed/denied
    status       = db.Column(db.String(20), default='pending')
    admin_note   = db.Column(db.Text, nullable=True)
    selected_fields = db.Column(db.Text, nullable=True)  # JSON list of field keys user wants erased
    requested_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    resolved_at  = db.Column(db.DateTime, nullable=True)
    resolved_by  = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    def __repr__(self):
        return f'<DsarRequest user={self.user_id} type={self.request_type} status={self.status}>'


class IncidentAlert(db.Model):
    """SOC Alerts generated by Module 2 Classifier."""
    __tablename__ = 'incident_alerts'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    incident_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    masked_log_context = db.Column(db.Text, nullable=False)
    cert_in_draft = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default='Open') # Open, Reviewed
    event_id = db.Column(db.String(64), nullable=True) # M3 Merkle Tree Audit Event ID
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<IncidentAlert {self.incident_type} {self.severity} event_id={self.event_id}>'
