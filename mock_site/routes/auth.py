"""
D-In-Sec Mock Site — Authentication Routes

SECURITY (Phase 1):
  All logs now use structured event-based format — no raw usernames,
  emails, or PII appear in system.log.
"""

import hashlib
import logging
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User, DsarRequest

auth_bp = Blueprint('auth', __name__)
logger = logging.getLogger('mock_site')


def _hash_value(val: str) -> str:
    """One-way hash for log correlation without exposing raw values."""
    return hashlib.sha256(val.encode()).hexdigest()[:12]


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Render login form and authenticate user."""
    if current_user.is_authenticated:
        return redirect(url_for('admin.dashboard')) if current_user.is_admin else redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user, remember=True)
            # Structured log — actor_id only, no username/email
            logger.info(f"event=LOGIN_SUCCESS actor_id={user.id}")
            flash('Login successful! Welcome back.', 'success')
            return redirect(url_for('admin.dashboard')) if user.is_admin else redirect(url_for('dashboard.index'))
        else:
            # Hashed username for correlation without exposing value
            logger.warning(
                f"event=LOGIN_FAIL username_hash={_hash_value(username)}"
            )
            flash('Invalid username or password.', 'error')

    return render_template('login.html')


@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    """Render signup form and create new user account."""
    if current_user.is_authenticated:
        return redirect(url_for('admin.dashboard')) if current_user.is_admin else redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')

        errors = []
        if not username or not email or not password:
            errors.append('All fields are required.')
        if password != confirm:
            errors.append('Passwords do not match.')
        if len(password) < 6:
            errors.append('Password must be at least 6 characters.')
        if User.query.filter_by(username=username).first():
            errors.append('Username already taken.')
        if User.query.filter_by(email=email).first():
            errors.append('Email already registered.')

        if errors:
            for err in errors:
                flash(err, 'error')
            return render_template('signup.html')

        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # Structured log — actor_id only, no username/email
        logger.info(f"event=SIGNUP_SUCCESS actor_id={new_user.id}")

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('signup.html')


@auth_bp.route('/logout')
@login_required
def logout():
    """Log out the current user and expire any active DSAR access reports."""
    actor_id = current_user.id
    
    # Security: Revoke access to the full data report upon logout
    active_dsars = DsarRequest.query.filter_by(
        user_id=actor_id, 
        request_type='ACCESS', 
        status='completed'
    ).all()
    for req in active_dsars:
        req.status = 'expired'
    if active_dsars:
        db.session.commit()

    logout_user()
    logger.info(f"event=LOGOUT actor_id={actor_id}")
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
