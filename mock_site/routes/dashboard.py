"""
D-In-Sec Mock Site — Dashboard Routes
Handles user dashboard, profile updates, document uploads,
and mock verification logic with raw PII logging.
"""

import os
import logging
from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, request, flash, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from models import db, Document

dashboard_bp = Blueprint('dashboard', __name__)
logger = logging.getLogger('mock_site')

# Allowed file extensions for document uploads
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}

# Valid document types
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
    """Check if the uploaded file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@dashboard_bp.route('/')
@login_required
def index():
    """Render the main user dashboard with profile and documents."""
    documents = Document.query.filter_by(user_id=current_user.id)\
        .order_by(Document.submitted_at.desc()).all()

    client_ip = request.remote_addr
    # --- RAW PII LOG: Dashboard access ---
    logger.info(
        f"User {current_user.username} ({current_user.email}) "
        f"accessed dashboard from IP {client_ip}"
    )

    return render_template('dashboard.html',
                           documents=documents,
                           doc_types=VALID_DOC_TYPES)


@dashboard_bp.route('/profile', methods=['POST'])
@login_required
def update_profile():
    """Update user profile PII fields."""
    client_ip = request.remote_addr

    # Collect profile fields
    full_name = request.form.get('full_name', '').strip()
    date_of_birth = request.form.get('date_of_birth', '').strip()
    phone = request.form.get('phone', '').strip()
    address = request.form.get('address', '').strip()
    aadhaar_number = request.form.get('aadhaar_number', '').strip()
    pan_number = request.form.get('pan_number', '').strip()

    # Update the user record
    current_user.full_name = full_name or current_user.full_name
    current_user.date_of_birth = date_of_birth or current_user.date_of_birth
    current_user.phone = phone or current_user.phone
    current_user.address = address or current_user.address
    current_user.aadhaar_number = aadhaar_number or current_user.aadhaar_number
    current_user.pan_number = pan_number or current_user.pan_number

    db.session.commit()

    # --- RAW PII LOG: Full profile data dump ---
    logger.info(
        f"User {current_user.username} ({current_user.email}) updated profile: "
        f"full_name={current_user.full_name}, "
        f"dob={current_user.date_of_birth}, "
        f"aadhaar={current_user.aadhaar_number}, "
        f"pan={current_user.pan_number}, "
        f"phone={current_user.phone}, "
        f"address={current_user.address} "
        f"from IP {client_ip}"
    )

    flash('Profile updated successfully.', 'success')
    return redirect(url_for('dashboard.index'))


@dashboard_bp.route('/upload', methods=['POST'])
@login_required
def upload_document():
    """Handle document file upload."""
    client_ip = request.remote_addr
    doc_type = request.form.get('doc_type', '').strip()
    file = request.files.get('document')

    # Validate document type
    if doc_type not in VALID_DOC_TYPES:
        flash('Invalid document type selected.', 'error')
        return redirect(url_for('dashboard.index'))

    # Validate file presence
    if not file or file.filename == '':
        flash('No file selected for upload.', 'error')
        return redirect(url_for('dashboard.index'))

    original_filename = file.filename

    # Check allowed extensions
    if not allowed_file(original_filename):
        # --- RAW LOG: Disallowed file extension ---
        logger.error(
            f"File upload rejected: user {current_user.username} "
            f"({current_user.email}) attempted to upload {original_filename} "
            f"(disallowed extension) from IP {client_ip}"
        )
        flash('File type not allowed. Please upload PDF, PNG, JPG, DOC, or DOCX files only.', 'error')
        return redirect(url_for('dashboard.index'))

    # Save file
    safe_name = secure_filename(original_filename)
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
    stored_name = f"{current_user.id}_{timestamp}_{safe_name}"
    upload_dir = current_app.config['UPLOAD_FOLDER']
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, stored_name)
    file.save(file_path)

    # Create document record
    doc = Document(
        user_id=current_user.id,
        doc_type=doc_type,
        file_name=original_filename,
        file_path=file_path,
        status='Pending',
    )
    db.session.add(doc)
    db.session.commit()

    # --- RAW PII LOG: Document upload ---
    logger.info(
        f"User {current_user.username} ({current_user.email}) uploaded document "
        f"{original_filename} (type: {doc_type}) from IP {client_ip}"
    )

    flash(f'Document "{original_filename}" uploaded successfully.', 'success')
    return redirect(url_for('dashboard.index'))


@dashboard_bp.route('/verify/<int:doc_id>', methods=['POST'])
@login_required
def verify_document(doc_id):
    """
    Mock verification logic.
    Checks that the user's profile fields are not empty,
    then marks the document as Verified or keeps it Pending.
    """
    client_ip = request.remote_addr
    doc = Document.query.get_or_404(doc_id)

    # Ensure the document belongs to the current user
    if doc.user_id != current_user.id:
        flash('Unauthorized access.', 'error')
        logger.warning(
            f"Unauthorized verify attempt: user {current_user.username} "
            f"({current_user.email}) tried to verify document ID {doc_id} "
            f"belonging to user_id {doc.user_id} from IP {client_ip}"
        )
        return redirect(url_for('dashboard.index'))

    # Mock verification: check that essential profile fields are filled
    required_fields = {
        'Full Name': current_user.full_name,
        'Date of Birth': current_user.date_of_birth,
        'Phone': current_user.phone,
        'Aadhaar Number': current_user.aadhaar_number,
    }
    missing = [name for name, val in required_fields.items() if not val]

    if missing:
        doc.status = 'Pending'
        db.session.commit()
        # --- RAW LOG: Verification failed ---
        logger.info(
            f"Document ID {doc.id} for user {current_user.email} "
            f"verification PENDING — missing fields: {', '.join(missing)} "
            f"from IP {client_ip}"
        )
        flash(f'Verification pending. Please complete: {", ".join(missing)}', 'warning')
    else:
        doc.status = 'Verified'
        doc.verified_at = datetime.now(timezone.utc)
        db.session.commit()
        # --- RAW PII LOG: Verification success ---
        logger.info(
            f"Document ID {doc.id} ({doc.file_name}) for user "
            f"{current_user.username} ({current_user.email}) marked as Verified "
            f"by system from IP {client_ip}"
        )
        flash(f'Document "{doc.file_name}" has been verified!', 'success')

    return redirect(url_for('dashboard.index'))
