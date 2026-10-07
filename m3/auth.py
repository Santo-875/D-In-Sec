"""
Token-Based Authentication & Role-Based Access Control (RBAC) for Module 3 (M3).

Provides a Flask decorator that enforces API key authentication and role-based
authorization on M3 endpoints.

Roles:
    ADMIN   — Key registration, freeze/unfreeze, audit pruning
    SERVICE — Tree updates (Module 2 pipeline)
    VIEWER  — Read-only: health, root, proofs, audit logs, verify endpoints

API keys and their roles are configured via the M3_API_KEYS environment variable
as a JSON object: {"key": "ROLE", ...}
"""

import json
import logging
import os
from functools import wraps

from flask import jsonify, request

logger = logging.getLogger("m3.auth")

# Role hierarchy — higher roles inherit lower role permissions
ROLE_HIERARCHY = {
    "ADMIN": {"ADMIN", "SERVICE", "VIEWER"},
    "SERVICE": {"SERVICE", "VIEWER"},
    "VIEWER": {"VIEWER"},
}

# Default keys used when M3_API_KEYS is not set (development mode only)
_DEV_KEYS = {
    "dev-admin-key": "ADMIN",
    "dev-service-key": "SERVICE",
    "dev-viewer-key": "VIEWER",
}


def _load_api_keys() -> dict[str, str]:
    """
    Loads API key → role mapping from M3_API_KEYS environment variable.
    Falls back to development keys if not set, with a warning.
    """
    raw = os.environ.get("M3_API_KEYS")
    if raw:
        try:
            keys = json.loads(raw)
            if isinstance(keys, dict) and keys:
                logger.info(f"Loaded {len(keys)} API key(s) from M3_API_KEYS.")
                return keys
        except json.JSONDecodeError as e:
            if os.environ.get("FLASK_ENV") == "production":
                raise RuntimeError(f"FATAL: M3_API_KEYS is not valid JSON and FLASK_ENV=production. Error: {e}")
            logger.error(f"M3_API_KEYS is not valid JSON: {e}. Falling back to dev keys.")

    if os.environ.get("FLASK_ENV") == "production":
        raise RuntimeError("FATAL: M3_API_KEYS environment variable is required in production (FLASK_ENV=production).")

    logger.warning(
        "M3_API_KEYS not set or empty. Using DEVELOPMENT keys. "
        "Do NOT use in production!"
    )
    return _DEV_KEYS.copy()


def get_api_keys() -> dict[str, str]:
    """Returns the current API key → role mapping. Reloads from env each call."""
    return _load_api_keys()


def authenticate_request() -> tuple[str | None, str | None]:
    """
    Extracts and validates the API key from the request.

    Returns:
        (api_key, role) if valid, (None, None) if missing or invalid.
    """
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        return None, None

    keys = get_api_keys()
    role = keys.get(api_key)
    return (api_key, role) if role else (api_key, None)


def require_role(*allowed_roles: str):
    """
    Flask route decorator that enforces token authentication and RBAC.

    Usage:
        @app.route('/admin-only')
        @require_role("ADMIN")
        def admin_endpoint():
            ...

        @app.route('/service-or-admin')
        @require_role("ADMIN", "SERVICE")
        def service_endpoint():
            ...

    Args:
        *allowed_roles: One or more role names that are permitted to access this endpoint.

    Returns:
        Decorated function that checks auth before executing the route handler.
    """
    allowed_set: set[str] = set(allowed_roles)

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            api_key, role = authenticate_request()

            if not api_key:
                return jsonify({
                    "error": "Authentication required",
                    "detail": "Provide a valid API key via X-API-Key header."
                }), 401

            if not role:
                return jsonify({
                    "error": "Invalid API key",
                    "detail": "The provided API key is not recognized."
                }), 401

            # Check if the user's role (or any role it inherits) is in the allowed set
            effective_roles = ROLE_HIERARCHY.get(role, {role})
            if not effective_roles.intersection(allowed_set):
                return jsonify({
                    "error": "Insufficient permissions",
                    "detail": f"Role '{role}' is not authorized for this endpoint. Required: {sorted(allowed_set)}",
                    "your_role": role
                }), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator
