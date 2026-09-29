import os
import requests
from flask import Blueprint, render_template, current_app
from models import IncidentAlert

soc_bp = Blueprint('soc', __name__)

M3_BASE_URL = os.environ.get("M3_API_URL", "http://127.0.0.1:5001/api/v1").rsplit("/tree/update", 1)[0]
M3_ADMIN_KEY = os.environ.get("M3_ADMIN_API_KEY", "dev-admin-key")

@soc_bp.route('/')
def index():
    """List all incidents."""
    incidents = IncidentAlert.query.order_by(IncidentAlert.created_at.desc()).all()
    return render_template('soc/index.html', incidents=incidents)

@soc_bp.route('/incident/<int:alert_id>')
def incident_detail(alert_id):
    """View incident details and M4 verification."""
    incident = IncidentAlert.query.get_or_404(alert_id)
    
    m4_data = None
    verification = None
    
    if incident.event_id:
        headers = {"X-API-Key": M3_ADMIN_KEY}
        # 1. Fetch M4 Payload
        try:
            r_m4 = requests.get(f"{M3_BASE_URL}/m4/payload/{incident.event_id}", headers=headers, timeout=3)
            if r_m4.status_code == 200:
                m4_data = r_m4.json()
        except Exception:
            pass
            
        # 2. Trigger on-the-fly verification
        if m4_data:
            try:
                tree_loc = m4_data.get("tree_update_location", {})
                req_body = {
                    "user_id": tree_loc.get("target_user_subroot"),
                    "leaf_id": tree_loc.get("target_leaf_id"),
                    "masked_pii_hash": tree_loc.get("masked_pii_hash"),
                    "real_data_hash": tree_loc.get("real_data_hash")
                }
                r_verify = requests.post(f"{M3_BASE_URL}/audit/verify", json=req_body, headers=headers, timeout=3)
                verification = r_verify.json()
            except Exception:
                verification = {"status": "ERROR", "reason": "M3 Verification Service Unreachable"}

    return render_template('soc/incident.html', incident=incident, m4_data=m4_data, verification=verification)
