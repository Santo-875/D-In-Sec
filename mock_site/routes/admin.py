"""
D-In-Sec — Admin Panel Routes
All routes protected by @admin_required decorator.
Logging: structured event-only, zero raw PII.
"""

import json
import logging
from datetime import datetime, timezone
from functools import wraps
from flask import (Blueprint, render_template, redirect, url_for,
                   request, flash, abort)
from flask_login import login_required, current_user
from models import db, User, Document, FieldSchema, DsarRequest
from vault.service import vault_get_profile, vault_get_file
from vault.token_manager import VaultAccessError
import os

admin_bp = Blueprint('admin', __name__)
logger = logging.getLogger('mock_site')

LOG_FILE = os.path.join(os.path.dirname(__file__), '..', 'logs', 'system.log')


# ── Decorator ────────────────────────────────────────────────────────────────

def admin_required(f):
    """Restrict route to admin users only."""
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            logger.warning(
                f"event=UNAUTHORIZED_ADMIN_ACCESS actor_id={current_user.id} "
                f"path={request.path}"
            )
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ── Dashboard ────────────────────────────────────────────────────────────────

@admin_bp.route('/')
@admin_required
def dashboard():
    total_users     = User.query.filter_by(is_admin=False).count()
    active_users    = User.query.filter_by(is_admin=False, is_active=True).count()
    pending_docs    = Document.query.filter_by(status='Pending').count()
    verified_docs   = Document.query.filter_by(status='Verified').count()
    pending_dsars   = DsarRequest.query.filter_by(status='pending').count()
    total_fields    = FieldSchema.query.count()

    # Read last 20 log lines for audit widget
    audit_lines = _read_log_tail(20)

    logger.info(f"event=ADMIN_DASHBOARD_ACCESS admin_id={current_user.id}")
    return render_template('admin/dashboard.html',
                           total_users=total_users,
                           active_users=active_users,
                           pending_docs=pending_docs,
                           verified_docs=verified_docs,
                           pending_dsars=pending_dsars,
                           total_fields=total_fields,
                           audit_lines=audit_lines)


# ── User Management ──────────────────────────────────────────────────────────

@admin_bp.route('/users')
@admin_required
def users():
    all_users = User.query.filter_by(is_admin=False).order_by(User.created_at.desc()).all()
    logger.info(f"event=ADMIN_USER_LIST admin_id={current_user.id}")
    return render_template('admin/users.html', users=all_users)


@admin_bp.route('/users/<int:user_id>/toggle', methods=['POST'])
@admin_required
def toggle_user(user_id):
    user = db.session.get(User, user_id)
    if not user or user.is_admin:
        flash('User not found.', 'error')
        return redirect(url_for('admin.users'))

    user.active = not user.active
    db.session.commit()
    action = 'ACTIVATE' if user.active else 'SUSPEND'
    logger.info(
        f"event=USER_{action} admin_id={current_user.id} target_user_id={user_id}"
    )
    flash(f'User {"activated" if user.active else "suspended"} successfully.', 'success')
    return redirect(url_for('admin.users'))


@admin_bp.route('/users/<int:user_id>/reset_password', methods=['POST'])
@admin_required
def reset_password(user_id):
    user = db.session.get(User, user_id)
    if not user or user.is_admin:
        flash('User not found.', 'error')
        return redirect(url_for('admin.users'))

    new_password = request.form.get('new_password', '').strip()
    if len(new_password) < 6:
        flash('Password must be at least 6 characters.', 'error')
        return redirect(url_for('admin.users'))

    user.set_password(new_password)
    db.session.commit()
    logger.info(
        f"event=ADMIN_PASSWORD_RESET admin_id={current_user.id} target_user_id={user_id}"
    )
    flash('Password reset successfully.', 'success')
    return redirect(url_for('admin.users'))


# ── Field Schema Builder ─────────────────────────────────────────────────────

@admin_bp.route('/schema')
@admin_required
def schema():
    fields = FieldSchema.query.order_by(FieldSchema.sort_order, FieldSchema.id).all()
    logger.info(f"event=ADMIN_SCHEMA_VIEW admin_id={current_user.id}")
    return render_template('admin/schema.html', fields=fields)


@admin_bp.route('/schema/add', methods=['POST'])
@admin_required
def schema_add():
    field_name   = request.form.get('field_name', '').strip()
    field_label  = request.form.get('field_label', '').strip()
    field_type   = request.form.get('field_type', 'text').strip()
    is_sensitive = request.form.get('is_sensitive') == 'on'
    is_required  = request.form.get('is_required') == 'on'
    placeholder  = request.form.get('placeholder', '').strip()
    help_text    = request.form.get('help_text', '').strip()
    sort_order   = int(request.form.get('sort_order', 0) or 0)

    # Sensitive-only fields
    pii_category  = request.form.get('pii_category', '').strip().upper() if is_sensitive else None
    preset_type   = request.form.get('preset_type', '').strip()          if is_sensitive else ''
    custom_regex  = request.form.get('custom_regex', '').strip()         if is_sensitive else ''

    if not field_name or not field_label:
        flash('Field name and label are required.', 'error')
        return redirect(url_for('admin.schema'))

    if FieldSchema.query.filter_by(field_name=field_name).first():
        flash(f'A field named "{field_name}" already exists.', 'error')
        return redirect(url_for('admin.schema'))

    # Auto-generate regex from preset type, else use custom regex
    regex_pattern = None
    mask_label    = None
    if is_sensitive:
        if custom_regex:
            regex_pattern = custom_regex
        elif preset_type:
            regex_pattern = _build_regex_from_preset(preset_type)
        if pii_category:
            mask_label = f'[REDACTED_{pii_category}]'

    new_field = FieldSchema(
        field_name=field_name, field_label=field_label, field_type=field_type,
        regex_pattern=regex_pattern, mask_label=mask_label,
        pii_category=pii_category, is_required=is_required,
        placeholder=placeholder or None, help_text=help_text or None,
        sort_order=sort_order,
    )
    db.session.add(new_field)
    db.session.commit()

    logger.info(
        f"event=SCHEMA_FIELD_ADD admin_id={current_user.id} "
        f"field={field_name} is_sensitive={is_sensitive} pii_category={pii_category}"
    )
    flash(f'Field "{field_label}" added successfully.', 'success')
    return redirect(url_for('admin.schema'))


@admin_bp.route('/schema/<int:field_id>/edit', methods=['GET', 'POST'])
@admin_required
def schema_edit(field_id):
    field = db.session.get(FieldSchema, field_id)
    if not field:
        flash('Field not found.', 'error')
        return redirect(url_for('admin.schema'))

    if request.method == 'POST':
        field.field_label = request.form.get('field_label', '').strip()
        field.field_type  = request.form.get('field_type', 'text').strip()
        is_sensitive = request.form.get('is_sensitive') == 'on'
        field.is_required = request.form.get('is_required') == 'on'
        field.placeholder = request.form.get('placeholder', '').strip() or None
        field.help_text   = request.form.get('help_text', '').strip() or None
        field.sort_order  = int(request.form.get('sort_order', 0) or 0)

        pii_category  = request.form.get('pii_category', '').strip().upper() if is_sensitive else None
        preset_type   = request.form.get('preset_type', '').strip()          if is_sensitive else ''
        custom_regex  = request.form.get('custom_regex', '').strip()         if is_sensitive else ''

        field.pii_category = pii_category

        if is_sensitive:
            if custom_regex:
                field.regex_pattern = custom_regex
            elif preset_type:
                field.regex_pattern = _build_regex_from_preset(preset_type)
            if pii_category:
                field.mask_label = f'[REDACTED_{pii_category}]'
        else:
            field.regex_pattern = None
            field.mask_label = None

        db.session.commit()
        logger.info(f"event=SCHEMA_FIELD_EDIT admin_id={current_user.id} field={field.field_name}")
        flash(f'Field "{field.field_label}" updated successfully.', 'success')
        return redirect(url_for('admin.schema'))

    return render_template('admin/schema_edit.html', field=field)


@admin_bp.route('/schema/<int:field_id>/delete', methods=['POST'])
@admin_required
def schema_delete(field_id):
    field = db.session.get(FieldSchema, field_id)
    if not field:
        flash('Field not found.', 'error')
        return redirect(url_for('admin.schema'))

    name = field.field_name
    db.session.delete(field)
    db.session.commit()
    logger.info(
        f"event=SCHEMA_FIELD_DELETE admin_id={current_user.id} field={name}"
    )
    flash(f'Field "{name}" deleted.', 'success')
    return redirect(url_for('admin.schema'))


# ── Document Review ───────────────────────────────────────────────────────────

@admin_bp.route('/documents')
@admin_required
def documents():
    # All documents with their owner info
    docs = (Document.query
            .join(User, Document.user_id == User.id)
            .add_columns(User.username, User.id.label('owner_id'))
            .order_by(Document.submitted_at.desc())
            .all())
    logger.info(f"event=ADMIN_DOC_LIST admin_id={current_user.id}")
    return render_template('admin/documents.html', docs=docs)


@admin_bp.route('/documents/<int:doc_id>/verify', methods=['POST'])
@admin_required
def verify_document(doc_id):
    doc = db.session.get(Document, doc_id)
    if not doc:
        flash('Document not found.', 'error')
        return redirect(url_for('admin.documents'))

    action     = request.form.get('action', '').strip()   # 'approve' or 'reject'
    admin_note = request.form.get('admin_note', '').strip()

    if action == 'approve':
        doc.status      = 'Verified'
        doc.verified_at = datetime.now(timezone.utc)
        doc.verified_by = current_user.id
        doc.admin_note  = admin_note or None
        db.session.commit()
        logger.info(
            f"event=DOCUMENT_VERIFY actor_id={doc.user_id} "
            f"admin_id={current_user.id} doc_id={doc_id} status=verified"
        )
        flash('Document verified successfully.', 'success')

    elif action == 'reject':
        doc.status     = 'Rejected'
        doc.verified_by = current_user.id
        doc.admin_note  = admin_note or None
        db.session.commit()
        logger.info(
            f"event=DOCUMENT_VERIFY actor_id={doc.user_id} "
            f"admin_id={current_user.id} doc_id={doc_id} status=rejected"
        )
        flash('Document rejected.', 'success')
    else:
        flash('Invalid action.', 'error')

    return redirect(url_for('admin.documents'))


# ── Audit Log Viewer ─────────────────────────────────────────────────────────

@admin_bp.route('/audit')
@admin_required
def audit():
    lines = _read_log_tail(200)
    logger.info(f"event=ADMIN_AUDIT_VIEW admin_id={current_user.id}")
    return render_template('admin/audit.html', lines=lines)


# ── DSAR Management ──────────────────────────────────────────────────────────

@admin_bp.route('/dsar')
@admin_required
def dsar():
    requests = (DsarRequest.query
                .join(User, DsarRequest.user_id == User.id)
                .add_columns(User.username)
                .order_by(DsarRequest.requested_at.desc())
                .all())
    logger.info(f"event=ADMIN_DSAR_LIST admin_id={current_user.id}")
    return render_template('admin/dsar.html', requests=requests)


@admin_bp.route('/dsar/<int:req_id>/resolve', methods=['POST'])
@admin_required
def dsar_resolve(req_id):
    """Step 1 admin action: approve (→ user picks fields) or deny."""
    dsar = db.session.get(DsarRequest, req_id)
    if not dsar:
        flash('Request not found.', 'error')
        return redirect(url_for('admin.dsar'))

    action     = request.form.get('action', '').strip()  # 'approve' or 'deny'
    admin_note = request.form.get('admin_note', '').strip()

    if action == 'approve':
        if dsar.request_type == 'ACCESS':
            # ACCESS: just mark completed — user can now see their data on DSAR page
            dsar.status      = 'completed'
            dsar.resolved_at = datetime.now(timezone.utc)
            dsar.resolved_by = current_user.id
            dsar.admin_note  = admin_note or None
            db.session.commit()
            logger.info(
                f"event=DSAR_REQUEST actor_id={dsar.user_id} "
                f"admin_id={current_user.id} request_type=ACCESS status=completed"
            )
            flash('ACCESS request approved. User can now view their full data summary.', 'success')

        elif dsar.request_type == 'ERASURE':
            # ERASURE step 1: tell user to select which fields to erase
            dsar.status      = 'approved'
            dsar.resolved_by = current_user.id
            dsar.admin_note  = admin_note or None
            db.session.commit()
            logger.info(
                f"event=DSAR_REQUEST actor_id={dsar.user_id} "
                f"admin_id={current_user.id} request_type=ERASURE status=approved"
            )
            flash('ERASURE approved. User will now be prompted to select specific fields.', 'success')

    elif action == 'deny':
        dsar.status      = 'denied'
        dsar.resolved_at = datetime.now(timezone.utc)
        dsar.resolved_by = current_user.id
        dsar.admin_note  = admin_note or None
        db.session.commit()
        logger.info(
            f"event=DSAR_REQUEST actor_id={dsar.user_id} "
            f"admin_id={current_user.id} request_type={dsar.request_type} status=denied"
        )
        flash('DSAR request denied.', 'success')
    else:
        flash('Invalid action.', 'error')

    return redirect(url_for('admin.dsar'))


@admin_bp.route('/dsar/<int:req_id>/final_confirm', methods=['POST'])
@admin_required
def dsar_final_confirm(req_id):
    """Step 2 admin action: final confirmation after user selected fields to erase."""
    dsar = db.session.get(DsarRequest, req_id)
    if not dsar or dsar.request_type != 'ERASURE' or dsar.status != 'fields_selected':
        flash('Invalid request state.', 'error')
        return redirect(url_for('admin.dsar'))

    action     = request.form.get('action', '').strip()  # 'confirm' or 'deny'
    admin_note = request.form.get('admin_note', '').strip()

    if action == 'confirm':
        user = db.session.get(User, dsar.user_id)
        selected = json.loads(dsar.selected_fields or '[]')

        if 'all' in selected or selected == ['all']:
            # Full erasure — wipe entire vault token
            if user and user.profile_token:
                _erase_vault_token(user.profile_token)
                user.profile_token = None
        else:
            # Partial erasure — remove only selected keys from vault blob
            if user and user.profile_token and selected:
                _erase_selected_fields(user.profile_token, user.id, selected)

        dsar.status      = 'completed'
        dsar.resolved_at = datetime.now(timezone.utc)
        dsar.admin_note  = admin_note or None
        db.session.commit()

        logger.info(
            f"event=DSAR_REQUEST actor_id={dsar.user_id} "
            f"admin_id={current_user.id} request_type=ERASURE "
            f"status=completed fields={selected}"
        )
        flash('Erasure completed. Selected data has been permanently deleted from vault.', 'success')

    elif action == 'deny':
        dsar.status      = 'denied'
        dsar.resolved_at = datetime.now(timezone.utc)
        dsar.admin_note  = admin_note or None
        db.session.commit()
        logger.info(
            f"event=DSAR_REQUEST actor_id={dsar.user_id} "
            f"admin_id={current_user.id} request_type=ERASURE status=denied_final"
        )
        flash('Erasure request denied at final stage.', 'success')

    return redirect(url_for('admin.dsar'))


# ── Helpers ──────────────────────────────────────────────────────────────────

def _read_log_tail(n: int) -> list[str]:
    """Read the last n lines from system.log."""
    log_path = os.path.normpath(LOG_FILE)
    if not os.path.exists(log_path):
        return []
    with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()
    return [l.rstrip() for l in lines[-n:]][::-1]


def _erase_vault_token(token_id: str):
    """Remove a token record from vault.db (full hard erasure)."""
    from vault.token_manager import _get_conn
    with _get_conn() as conn:
        conn.execute("DELETE FROM vault_tokens WHERE token_id = ?", (token_id,))
        conn.commit()


def _erase_selected_fields(token_id: str, user_id: int, fields: list):
    """Remove specific keys from a vault profile blob (partial erasure)."""
    from vault.service import vault_get_profile, vault_update_profile
    profile = vault_get_profile(token_id, user_id)
    for key in fields:
        profile.pop(key, None)
    vault_update_profile(token_id, user_id, profile)


def _build_regex_from_preset(preset_type: str) -> str:
    """Return a sensible regex for a known PII preset type."""
    PRESETS = {
        'aadhaar':      r'\b\d{4}[- ]?\d{4}[- ]?\d{4}\b',
        'pan':          r'\b[A-Z]{5}\d{4}[A-Z]\b',
        'phone':        r'\b[6-9]\d{9}\b',
        'email':        r'\b[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}\b',
        'dob':          r'\b\d{2}[/-]\d{2}[/-]\d{4}\b',
        'passport':     r'\b[A-Z]{1}\d{7}\b',
        'voter_id':     r'\b[A-Z]{3}\d{7}\b',
        'ifsc':         r'\b[A-Z]{4}0[A-Z0-9]{6}\b',
        'credit_card':  r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
        'pincode':      r'\b[1-9]\d{5}\b',
        'name':         r'[A-Za-z][A-Za-z ]{1,50}',
        'address':      r'.{10,200}',
        'custom':       r'.+',
    }
    return PRESETS.get(preset_type.lower(), r'.+')
