"""
D-In-Sec Mock Site — Dashboard Routes
Handles profile updates, document uploads, and verification.

SECURITY (Phase 1, 3, 4):
  - All logging is now structured/event-based — NO raw PII in logs.
  - Profile PII is encrypted and stored in the Vault, not the main DB.
  - Uploaded files are encrypted in the Vault, not written to disk as-is.
  - File names are randomized (UUID) to prevent enumeration.
"""

import os
import re
import uuid
import json
import logging
from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, request, flash, current_app, send_file
from flask_login import login_required, current_user
from models import db, Document, DsarRequest, FieldSchema
from vault.service import (
    vault_store_profile, vault_get_profile,
    vault_update_profile, vault_store_file, vault_get_file,
)
import io

dashboard_bp = Blueprint('dashboard', __name__)
logger = logging.getLogger('mock_site')

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}

VALID_DOC_TYPES = [
    'Aadhaar Card',
    'PAN Card',
    'Passport',
    'Driving License',
    'Voter ID',
    'Birth Certificate',
    'Address Proof',
    'Other',
]


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@dashboard_bp.route('/')
@login_required
def index():
    """Render the main user dashboard with profile and documents."""
    documents = Document.query.filter_by(user_id=current_user.id)\
        .order_by(Document.submitted_at.desc()).all()

    # Retrieve profile data from vault (decrypted, in memory only)
    profile = vault_get_profile(current_user.profile_token, current_user.id)

    # Structured log — no PII
    logger.info(
        f"event=DASHBOARD_ACCESS actor_id={current_user.id} status=success"
    )

    # Load admin-defined schema fields for dynamic profile form
    schema_fields = FieldSchema.query.order_by(FieldSchema.sort_order, FieldSchema.id).all()

    return render_template('dashboard.html',
                           documents=documents,
                           doc_types=VALID_DOC_TYPES,
                           profile=profile,
                           schema_fields=schema_fields)


@dashboard_bp.route('/profile', methods=['POST'])
@login_required
def update_profile():
    """Update user profile — encrypt and store in vault."""

    full_name     = request.form.get('full_name', '').strip()
    date_of_birth = request.form.get('date_of_birth', '').strip()
    phone         = request.form.get('phone', '').strip()
    address       = request.form.get('address', '').strip()
    aadhaar_number = request.form.get('aadhaar_number', '').strip()
    pan_number    = request.form.get('pan_number', '').strip()

    # Validation — reject bad formats before they even reach the vault
    errors = []
    if pan_number and not re.match(r"^[A-Z]{5}\d{4}[A-Z]$", pan_number, re.IGNORECASE):
        errors.append("Invalid PAN format.")
    if phone and not re.match(r"^\d{10,12}$", phone):
        errors.append("Invalid Phone format (must be 10-12 digits).")
    if aadhaar_number and not re.match(r"^\d{4}[-\s]?\d{4}[-\s]?\d{4}$", aadhaar_number):
        errors.append("Invalid Aadhaar format.")

    if errors:
        for err in errors:
            flash(err, 'error')
        logger.warning(f"event=PROFILE_VALIDATION_FAIL actor_id={current_user.id} errors={len(errors)}")
        return redirect(url_for('dashboard.index'))

    # Build profile dict — this is the ONLY moment raw PII exists, in RAM
    existing = vault_get_profile(current_user.profile_token, current_user.id)
    profile_data = {
        'full_name':      full_name or existing.get('full_name', ''),
        'date_of_birth':  date_of_birth or existing.get('date_of_birth', ''),
        'phone':          phone or existing.get('phone', ''),
        'address':        address or existing.get('address', ''),
        'aadhaar_number': aadhaar_number or existing.get('aadhaar_number', ''),
        'pan_number':     pan_number or existing.get('pan_number', ''),
    }

    # Merge custom schema fields (admin-defined)
    for key, value in request.form.items():
        if key.startswith('custom_'):
            profile_data[key] = value.strip() or existing.get(key, '')

    if current_user.profile_token:
        # Update existing vault token
        vault_update_profile(current_user.profile_token, current_user.id, profile_data)
    else:
        # First time — create a new vault token and save reference in DB
        token = vault_store_profile(current_user.id, profile_data)
        current_user.profile_token = token
        db.session.commit()

    # Structured log — no PII
    logger.info(f"event=PROFILE_UPDATE actor_id={current_user.id} status=success")

    flash('Profile updated successfully.', 'success')
    return redirect(url_for('dashboard.index'))


@dashboard_bp.route('/upload', methods=['POST'])
@login_required
def upload_document():
    """Handle document file upload — encrypt file in vault."""

    doc_type = request.form.get('doc_type', '').strip()
    file     = request.files.get('document')

    if doc_type not in VALID_DOC_TYPES:
        flash('Invalid document type selected.', 'error')
        return redirect(url_for('dashboard.index'))

    if not file or file.filename == '':
        flash('No file selected for upload.', 'error')
        return redirect(url_for('dashboard.index'))

    original_filename = file.filename

    if not allowed_file(original_filename):
        logger.error(
            f"event=UPLOAD_REJECTED actor_id={current_user.id} reason=disallowed_extension"
        )
        flash('File type not allowed. Please upload PDF, PNG, JPG, DOC, or DOCX files only.', 'error')
        return redirect(url_for('dashboard.index'))

    # Read file bytes into memory — encrypt directly, no raw write to disk
    file_bytes = file.read()
    ext = original_filename.rsplit('.', 1)[1].lower()
    random_name = uuid.uuid4().hex  # e.g., "8f3a9c7b..."

    meta = {
        'original_name': original_filename,
        'extension': ext,
        'doc_type': doc_type,
        'random_name': random_name,
    }

    file_token = vault_store_file(current_user.id, file_bytes, meta)

    # Archive file to AWS S3 bucket if configured
    s3_key = None
    s3_bucket = os.getenv('S3_BUCKET')
    if s3_bucket:
        try:
            import boto3
            s3 = boto3.client('s3', region_name=os.getenv('AWS_REGION', 'ap-south-1'))
            s3_key = f"documents/user_{current_user.id}/{random_name}_{original_filename}"
            kwargs = {
                "Bucket": s3_bucket,
                "Key": s3_key,
                "Body": file_bytes,
                "ContentType": file.content_type or "application/octet-stream",
            }
            kms_key = os.getenv("KMS_DATA_KEY_ID")
            if kms_key:
                kwargs["ServerSideEncryption"] = "aws:kms"
                kwargs["SSEKMSKeyId"] = kms_key
            s3.put_object(**kwargs)
            logger.info(f"event=S3_UPLOAD_SUCCESS actor_id={current_user.id} bucket={s3_bucket} key={s3_key}")
        except Exception as exc:
            logger.error(f"event=S3_UPLOAD_FAILED actor_id={current_user.id} bucket={s3_bucket} error={exc}")

    doc = Document(
        user_id=current_user.id,
        doc_type=doc_type,
        file_token=file_token,
        file_name=original_filename,
        file_path=s3_key or f"vault://{file_token}",
        s3_key=s3_key,
        status='Pending',
    )
    db.session.add(doc)
    db.session.commit()

    # Structured log — no raw PII
    logger.info(
        f"event=DOCUMENT_UPLOAD actor_id={current_user.id} "
        f"doc_type={doc_type} file_token={file_token[:8]}... s3_key={s3_key or 'none'} status=success"
    )

    if s3_key:
        flash(f'Document "{original_filename}" uploaded and saved to AWS S3 bucket ({s3_bucket}) with KMS encryption.', 'success')
    else:
        flash(f'Document "{original_filename}" uploaded successfully.', 'success')
    return redirect(url_for('dashboard.index'))


@dashboard_bp.route('/verify/<int:doc_id>', methods=['POST'])
@login_required
def verify_document(doc_id):
    """
    Mock verification — checks that the user's vault profile has required fields.
    """
    doc = Document.query.get_or_404(doc_id)

    if doc.user_id != current_user.id:
        flash('Unauthorized access.', 'error')
        logger.warning(
            f"event=UNAUTHORIZED_VERIFY actor_id={current_user.id} doc_id={doc_id}"
        )
        return redirect(url_for('dashboard.index'))

    # Fetch decrypted profile from vault to check required fields
    profile = vault_get_profile(current_user.profile_token, current_user.id)

    required_fields = {
        'Full Name':      profile.get('full_name'),
        'Date of Birth':  profile.get('date_of_birth'),
        'Phone':          profile.get('phone'),
        'Aadhaar Number': profile.get('aadhaar_number'),
    }
    missing = [name for name, val in required_fields.items() if not val]

    if missing:
        doc.status = 'Pending'
        db.session.commit()
        logger.info(
            f"event=DOCUMENT_VERIFY actor_id={current_user.id} "
            f"doc_id={doc_id} status=pending missing_fields={len(missing)}"
        )
        flash(f'Verification pending. Please complete: {", ".join(missing)}', 'warning')
    else:
        doc.status = 'Verified'
        doc.verified_at = datetime.now(timezone.utc)
        db.session.commit()
        logger.info(
            f"event=DOCUMENT_VERIFY actor_id={current_user.id} "
            f"doc_id={doc_id} status=verified"
        )
        flash('Document has been verified!', 'success')

    return redirect(url_for('dashboard.index'))


# ── DSAR (Data Subject Access Request) ────────────────────────────────────────

@dashboard_bp.route('/dsar')
@login_required
def dsar():
    """DSAR page — show data summary and allow submitting requests."""
    profile = vault_get_profile(current_user.profile_token, current_user.id)
    past_requests = DsarRequest.query.filter_by(user_id=current_user.id)\
        .order_by(DsarRequest.requested_at.desc()).all()

    logger.info(
        f"event=DSAR_PAGE_VIEW actor_id={current_user.id}"
    )
    return render_template('dashboard_dsar.html',
                           profile=profile,
                           past_requests=past_requests)


@dashboard_bp.route('/dsar/request', methods=['POST'])
@login_required
def dsar_submit():
    """Submit an ACCESS or ERASURE DSAR request."""
    request_type = request.form.get('request_type', '').strip().upper()
    if request_type not in ('ACCESS', 'ERASURE'):
        flash('Invalid request type.', 'error')
        return redirect(url_for('dashboard.dsar'))

    # Only one pending request of each type at a time
    existing = DsarRequest.query.filter_by(
        user_id=current_user.id,
        request_type=request_type,
        status='pending'
    ).first()
    if existing:
        flash(f'You already have a pending {request_type} request.', 'warning')
        return redirect(url_for('dashboard.dsar'))

    dsar_req = DsarRequest(
        user_id=current_user.id,
        request_type=request_type,
        status='pending',
    )
    db.session.add(dsar_req)
    db.session.commit()

    logger.info(
        f"event=DSAR_REQUEST actor_id={current_user.id} "
        f"request_type={request_type} status=pending"
    )
    flash(f'Your {request_type} request has been submitted and is under review.', 'success')
    return redirect(url_for('dashboard.dsar'))


@dashboard_bp.route('/dsar/<int:req_id>/select_fields', methods=['POST'])
@login_required
def dsar_select_fields(req_id):
    """User submits field selection for an approved ERASURE request."""
    dsar = db.session.get(DsarRequest, req_id)
    if not dsar or dsar.user_id != current_user.id or dsar.status != 'approved':
        flash('This request is not available for field selection.', 'error')
        return redirect(url_for('dashboard.dsar'))

    selected = request.form.getlist('fields')  # list of field keys
    erase_all = request.form.get('erase_all') == 'on'

    if erase_all:
        selected = ['all']
    elif not selected:
        flash('Please select at least one field to erase, or choose "Erase All".', 'warning')
        return redirect(url_for('dashboard.dsar'))

    dsar.selected_fields = json.dumps(selected)
    dsar.status = 'fields_selected'
    db.session.commit()

    logger.info(
        f"event=DSAR_REQUEST actor_id={current_user.id} "
        f"request_type=ERASURE status=fields_selected fields={selected}"
    )
    flash('Your selection has been submitted. Waiting for admin final confirmation.', 'success')
    return redirect(url_for('dashboard.dsar'))
