"""
D-In-Sec Mock Site — Database Models
SQLAlchemy models for User accounts and Document uploads.
"""

from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):
    """
    User account model.
    Stores authentication credentials and heavy PII fields
    (name, DOB, Aadhaar, PAN, phone, address) used for
    document verification workflows.
    """
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)

    # --- PII Fields ---
    full_name = db.Column(db.String(200), nullable=True)
    date_of_birth = db.Column(db.String(10), nullable=True)       # YYYY-MM-DD
    phone = db.Column(db.String(20), nullable=True)
    address = db.Column(db.Text, nullable=True)
    aadhaar_number = db.Column(db.String(14), nullable=True)       # XXXX-XXXX-XXXX
    pan_number = db.Column(db.String(10), nullable=True)           # ABCDE1234F

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
    Tracks file metadata and verification status for each
    document submitted by a user.
    """
    __tablename__ = 'documents'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    doc_type = db.Column(db.String(50), nullable=False)           # Aadhaar Card, PAN Card, etc.
    file_name = db.Column(db.String(255), nullable=False)         # Original filename
    file_path = db.Column(db.String(500), nullable=False)         # Server-side path
    status = db.Column(db.String(20), default='Pending')          # Pending / Verified / Rejected
    submitted_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    verified_at = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<Document {self.file_name} [{self.status}]>'
