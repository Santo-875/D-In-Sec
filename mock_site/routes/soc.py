import os
import json
import logging
import requests
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, Response
from models import IncidentAlert

logger = logging.getLogger("mock_site.soc")
soc_bp = Blueprint('soc', __name__)

def _get_m3_base_url():
    if "M3_BASE_URL" in os.environ:
        return os.environ["M3_BASE_URL"].rstrip("/")
    api_url = os.environ.get("M3_API_URL", "http://127.0.0.1:5001")
    if "/api/v1" in api_url:
        return api_url.split("/api/v1")[0].rstrip("/")
    if "/v1" in api_url:
        return api_url.split("/v1")[0].rstrip("/")
    return api_url.rstrip("/")

def _get_m3_headers():
    admin_key = os.environ.get("M3_ADMIN_API_KEY", "dev-admin-key")
    return {"X-API-Key": admin_key, "Content-Type": "application/json"}

# ── Safe M3 Helper Functions (Timeouts + Error States) ─────────────────────

def fetch_cloud_status():
    """Queries M3 /readyz and storage config with timeout and graceful error fallback."""
    base_url = _get_m3_base_url()
    headers = _get_m3_headers()
    backend = os.environ.get("STORAGE_BACKEND", "local")
    signer = os.environ.get("SIGNER_BACKEND", "local")
    bucket = os.environ.get("S3_BUCKET", "local_storage")

    status_data = {
        "backend": backend,
        "signer": signer,
        "bucket": bucket,
        "storage_healthy": False,
        "pending_uploads": 0,
        "status": "UNREACHABLE",
        "last_anchor": None,
        "master_root": None,
        "error": None
    }

    try:
        r = requests.get(f"{base_url}/readyz", headers=headers, timeout=3)
        if r.status_code in [200, 503]:
            data = r.json()
            status_data["storage_healthy"] = data.get("storage_healthy", False)
            status_data["pending_uploads"] = data.get("pending_uploads_backlog", 0)
            status_data["status"] = data.get("status", "unknown").upper()
    except Exception as exc:
        logger.warning("Error fetching M3 /readyz: %s", exc)
        status_data["error"] = f"M3 probe failed: {str(exc)}"

    try:
        r_root = requests.get(f"{base_url}/api/v1/tree/root", headers=headers, timeout=3)
        if r_root.status_code == 200:
            root_info = r_root.json()
            status_data["master_root"] = root_info.get("master_root")
            chain = root_info.get("permanent_root_chain", [])
            if chain:
                status_data["last_anchor"] = chain[-1]
    except Exception as exc:
        logger.debug("Error fetching M3 /tree/root: %s", exc)

    return status_data

def fetch_alerts():
    """Queries M3 /v1/alerts with timeout and error fallback."""
    base_url = _get_m3_base_url()
    headers = _get_m3_headers()
    try:
        r = requests.get(f"{base_url}/v1/alerts", headers=headers, timeout=3)
        if r.status_code == 200:
            return r.json().get("alerts", [])
    except Exception as exc:
        logger.warning("Error fetching M3 /v1/alerts: %s", exc)
    return []

def fetch_certin_summary():
    """Queries M3 /v1/export/certin with timeout and error fallback."""
    base_url = _get_m3_base_url()
    headers = _get_m3_headers()
    try:
        r = requests.get(f"{base_url}/v1/export/certin", headers=headers, timeout=3)
        if r.status_code == 200:
            return r.json()
    except Exception as exc:
        logger.warning("Error fetching M3 /v1/export/certin: %s", exc)
    return {"logs_count": 0, "summaries_count": 0, "summaries": []}

def fetch_model_registry():
    """Queries M3 /v1/admin/model/registry with timeout and error fallback."""
    base_url = _get_m3_base_url()
    headers = _get_m3_headers()
    try:
        r = requests.get(f"{base_url}/v1/admin/model/registry", headers=headers, timeout=3)
        if r.status_code == 200:
            return r.json().get("models", [])
    except Exception as exc:
        logger.warning("Error fetching M3 model registry: %s", exc)
    return []

def execute_full_verification():
    """Calls M3 /v1/verify/full and formats step-by-step verification progress."""
    base_url = _get_m3_base_url()
    headers = _get_m3_headers()
    steps = [
        {"name": "1. Recompute Merkle Root from SQLite", "status": "PENDING", "detail": "Pending calculation"},
        {"name": "2. Retrieve Latest Root Anchor from Storage", "status": "PENDING", "detail": "Pending fetch"},
        {"name": "3. Compare Database Root vs Anchored Root", "status": "PENDING", "detail": "Pending comparison"},
        {"name": "4. Verify Checkpoint Digital Signature (KMS / Local)", "status": "PENDING", "detail": "Pending signature check"}
    ]

    try:
        r = requests.get(f"{base_url}/v1/verify/full", headers=headers, timeout=5)
        res = r.json() if r.content else {}
        status = res.get("status", "ERROR")
        db_root = res.get("db_root")
        anchored_root = res.get("anchored_root")
        anchor_key = res.get("anchor_key")

        # Step 1
        if db_root:
            steps[0]["status"] = "PASSED"
            steps[0]["detail"] = f"DB Master Root: {db_root[:16]}..."
        else:
            steps[0]["status"] = "FAILED"
            steps[0]["detail"] = "Unable to compute master root"

        # Step 2
        if anchor_key or status in ["VERIFIED", "TAMPER"]:
            steps[1]["status"] = "PASSED"
            steps[1]["detail"] = f"Anchor Key: {anchor_key or 'Retrieved'} (Root: {(anchored_root or '')[:16]}...)"
        elif status == "UNVERIFIED":
            steps[1]["status"] = "WARNING"
            steps[1]["detail"] = res.get("reason", "No anchors available in storage")
        else:
            steps[1]["status"] = "FAILED"
            steps[1]["detail"] = res.get("reason", "Anchor unreachable")

        # Step 3
        if status == "VERIFIED":
            steps[2]["status"] = "PASSED"
            steps[2]["detail"] = "Roots match perfectly without divergence"
            steps[3]["status"] = "PASSED"
            steps[3]["detail"] = "Cryptographic digital signature verified successfully"
        elif status == "TAMPER":
            steps[2]["status"] = "FAILED"
            steps[2]["detail"] = res.get("reason", "Divergence detected between DB and anchor!")
            steps[3]["status"] = "FAILED"
            steps[3]["detail"] = "System frozen due to integrity violation"
        else:
            steps[2]["status"] = "SKIPPED"
            steps[2]["detail"] = res.get("reason", "Skipped due to unverified anchor")
            steps[3]["status"] = "SKIPPED"
            steps[3]["detail"] = "Skipped"

        return {
            "status": status,
            "message": res.get("message") or res.get("reason") or "Completed",
            "db_root": db_root,
            "anchored_root": anchored_root,
            "anchor_key": anchor_key,
            "steps": steps,
            "raw": res
        }
    except Exception as exc:
        logger.error("Full verification request failed: %s", exc)
        for s in steps:
            s["status"] = "FAILED"
            s["detail"] = f"Error: {str(exc)}"
        return {
            "status": "ERROR",
            "message": f"M3 connection error: {str(exc)}",
            "steps": steps,
            "raw": {"error": str(exc)}
        }

# ── Routes ─────────────────────────────────────────────────────────────────

@soc_bp.route('/')
def index():
    """SOC Dashboard with all security panels."""
    incidents = IncidentAlert.query.order_by(IncidentAlert.created_at.desc()).all()
    cloud_status = fetch_cloud_status()
    alerts = fetch_alerts()
    certin_bundle = fetch_certin_summary()
    models = fetch_model_registry()

    verification = None
    if request.args.get("verified") == "1":
        verification = execute_full_verification()

    return render_template(
        'soc/index.html',
        incidents=incidents,
        cloud_status=cloud_status,
        alerts=alerts,
        certin_bundle=certin_bundle,
        models=models,
        verification=verification
    )

@soc_bp.route('/verify/full', methods=['GET', 'POST'])
def run_full_verify():
    """Triggers full verification of Merkle tree against storage anchor."""
    verification = execute_full_verification()
    if request.headers.get("Accept") == "application/json" or request.is_json:
        return jsonify(verification)
    if verification["status"] == "VERIFIED":
        flash("Full Merkle verification PASSED: DB root matches storage anchor.", "success")
    elif verification["status"] == "TAMPER":
        flash(f"CRITICAL TAMPER DETECTED: {verification['message']}", "danger")
    else:
        flash(f"Verification status: {verification['status']} - {verification['message']}", "warning")
    return redirect(url_for('soc.index', verified=1))

@soc_bp.route('/export/certin')
def export_certin():
    """Exports CERT-In logs and summaries bundle."""
    base_url = _get_m3_base_url()
    headers = _get_m3_headers()
    try:
        r = requests.get(f"{base_url}/v1/export/certin", headers=headers, timeout=5)
        if r.status_code == 200:
            return Response(
                r.content,
                mimetype="application/json",
                headers={"Content-Disposition": "attachment;filename=certin_export_bundle.json"}
            )
        return jsonify({"error": "Failed to fetch export from M3", "status_code": r.status_code}), r.status_code
    except Exception as exc:
        return jsonify({"error": f"M3 unreachable: {str(exc)}"}), 503

@soc_bp.route('/model/rollback/<version>', methods=['POST'])
def rollback_model(version):
    """Rolls back the ML classifier model to an earlier version."""
    base_url = _get_m3_base_url()
    headers = _get_m3_headers()
    try:
        r = requests.post(f"{base_url}/v1/admin/model/rollback/{version}", headers=headers, timeout=5)
        if r.status_code == 200:
            flash(f"Successfully rolled back model to version '{version}'.", "success")
        else:
            flash(f"Failed to roll back model: {r.text}", "danger")
    except Exception as exc:
        flash(f"Error communicating with M3 sidecar: {str(exc)}", "danger")
    return redirect(url_for('soc.index'))

@soc_bp.route('/anchor', methods=['POST'])
def trigger_manual_anchor():
    """Manually triggers an S3 root anchor checkpoint."""
    base_url = _get_m3_base_url()
    headers = _get_m3_headers()
    try:
        r = requests.post(f"{base_url}/v1/admin/anchor", headers=headers, timeout=5)
        if r.status_code == 200:
            flash("Manual root anchor triggered successfully.", "success")
        else:
            flash(f"Anchor failed: {r.text}", "warning")
    except Exception as exc:
        flash(f"Error communicating with M3 sidecar: {str(exc)}", "danger")
    return redirect(url_for('soc.index'))

@soc_bp.route('/incident/<int:alert_id>')
def incident_detail(alert_id):
    """View incident details and M4 verification."""
    incident = IncidentAlert.query.get_or_404(alert_id)
    m4_data = None
    verification = None
    base_url = _get_m3_base_url()
    headers = _get_m3_headers()

    if incident.event_id:
        try:
            r_m4 = requests.get(f"{base_url}/api/v1/m4/payload/{incident.event_id}", headers=headers, timeout=3)
            if r_m4.status_code == 200:
                m4_data = r_m4.json()
        except Exception as exc:
            logger.warning("Error fetching M4 payload for event %s: %s", incident.event_id, exc)

        if m4_data:
            try:
                tree_loc = m4_data.get("tree_update_location", {})
                req_body = {
                    "user_id": tree_loc.get("target_user_subroot"),
                    "leaf_id": tree_loc.get("target_leaf_id"),
                    "masked_pii_hash": tree_loc.get("masked_pii_hash"),
                    "real_data_hash": tree_loc.get("real_data_hash")
                }
                r_verify = requests.post(f"{base_url}/audit/verify", json=req_body, headers=headers, timeout=3)
                verification = r_verify.json()
            except Exception as exc:
                verification = {"status": "ERROR", "reason": f"M3 Verification Service Unreachable: {str(exc)}"}

    return render_template('soc/incident.html', incident=incident, m4_data=m4_data, verification=verification)
