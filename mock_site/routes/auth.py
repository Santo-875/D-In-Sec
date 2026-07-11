"""
D-In-Sec Mock Site — Authentication Routes
Handles user Login, Signup, and Logout with raw PII logging.
"""

import logging
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User

auth_bp = Blueprint('auth', __name__)
logger = logging.getLogger('mock_site')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Render login form and authenticate user."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        client_ip = request.remote_addr

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user, remember=True)
            # --- RAW PII LOG: Successful login ---
            logger.info(
                f"User {user.username} ({user.email}) logged in successfully "
                f"from IP {client_ip}"
            )
            flash('Login successful! Welcome back.', 'success')
            return redirect(url_for('dashboard.index'))
        else:
            # --- RAW LOG: Failed login attempt ---
            logger.warning(
                f"Failed login attempt for username '{username}' "
                f"from IP {client_ip}"
            )
            flash('Invalid username or password.', 'error')

    return render_template('login.html')


@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    """Render signup form and create new user account."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        client_ip = request.remote_addr

        # Basic validation
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

        # Create user
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # --- RAW PII LOG: New account created ---
        logger.info(
            f"New user account created: username={new_user.username}, "
            f"email={new_user.email} from IP {client_ip}"
        )

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('signup.html')


@auth_bp.route('/logout')
@login_required
def logout():
    """Log out the current user."""
    client_ip = request.remote_addr
    # --- RAW PII LOG: Logout ---
    logger.info(
        f"User {current_user.username} ({current_user.email}) "
        f"logged out from IP {client_ip}"
    )
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
