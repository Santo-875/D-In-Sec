"""
create_admin.py — One-time CLI script to promote a user to admin.
Run: python create_admin.py
"""

from app import create_app
from models import db, User
from werkzeug.security import generate_password_hash

app = create_app()

with app.app_context():
    print("\n=== D-In-Sec Admin Account Setup ===\n")

    mode = input("Create NEW admin or PROMOTE existing user? [new/promote]: ").strip().lower()

    if mode == 'new':
        username = input("Username: ").strip()
        email    = input("Email:    ").strip()
        password = input("Password: ").strip()

        if User.query.filter_by(username=username).first():
            print(f"\nError: Username '{username}' already exists.")
        elif User.query.filter_by(email=email).first():
            print(f"\nError: Email '{email}' already registered.")
        elif len(password) < 6:
            print("\nError: Password must be at least 6 characters.")
        else:
            admin = User(username=username, email=email, is_admin=True)
            admin.set_password(password)
            db.session.add(admin)
            db.session.commit()
            print(f"\n✓ Admin account '{username}' created successfully.")
            print("  Login at: http://127.0.0.1:5000/auth/login")
            print("  Admin panel: http://127.0.0.1:5000/admin/\n")

    elif mode == 'promote':
        username = input("Username to promote: ").strip()
        user = User.query.filter_by(username=username).first()
        if not user:
            print(f"\nError: User '{username}' not found.")
        else:
            user.is_admin = True
            db.session.commit()
            print(f"\n✓ User '{username}' promoted to admin.")
            print("  Admin panel: http://127.0.0.1:5000/admin/\n")
    else:
        print("Unknown option. Use 'new' or 'promote'.")
