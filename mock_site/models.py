"""
D-In-Sec Mock Site — Database Models
SQLAlchemy models for User accounts and Document uploads.

SECURITY NOTE (Phase 2):
  Raw PII fields (name, DOB, phone, Aadhaar, PAN, address) have been
  removed from this model. All PII is now stored encrypted inside the
  Vault (vault/service.py). Only a profile_token reference is kept here.
  If the DB leaks, an attacker gets only useless UUID tokens.
"""

from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):
    """
    User account model.
    Stores authentication credentials and a vault token reference.
    No raw PII is stored here.
    """
    __tablename__ = 'users'

    id            = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username      = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email         = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)

    # Vault token reference — points to encrypted PII in vault.db
    profile_token = db.Column(db.String(64), nullable=True)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationship
    documents = db.relationship('Document', backref='owner', lazy=True,
                                cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class Document(db.Model):
    """
    Uploaded document model.
    Stores a vault token reference to the encrypted file — no raw file path
    or original filename is kept here.
    """
    __tablename__ = 'documents'

    id          = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id     = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    doc_type    = db.Column(db.String(50), nullable=False)
    file_token  = db.Column(db.String(64), nullable=False)   # Vault reference
    status      = db.Column(db.String(20), default='Pending')
    submitted_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    verified_at = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<Document [{self.doc_type}] [{self.status}]>'
