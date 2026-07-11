"""
D-In-Sec Mock Site — Route Blueprints
Registers all Flask blueprints for the application.
"""

from routes.auth import auth_bp
from routes.dashboard import dashboard_bp


def register_blueprints(app):
    """Register all route blueprints with the Flask app."""
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
