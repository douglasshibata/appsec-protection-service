import os
from fastapi import FastAPI, Request, Form, Query, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import uvicorn
import logging

from .database import (
    get_metrics, get_audit_logs, get_active_blocks, block_ip,
    unblock_ip, set_config, get_config
)
from .anomaly_detector import AnomalyDetector
from .alert_manager import AlertManager
from .security_middleware import SecurityMiddleware

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("appsec.main")

app = FastAPI(
    title="AppSec Protection Engine Gateway",
    description="Microserviço autônomo para detecção e mitigação de ameaças OWASP Top 10 e abuso de APIs em tempo real.",
    version="1.0.0"
)

# Initialize Security Components
anomaly_detector = AnomalyDetector()
alert_manager = AlertManager(webhook_url=get_config("webhook_url", ""))

# Configure templates path
templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)

# Register Security Interceptor Middleware
app.add_middleware(
    SecurityMiddleware,
    anomaly_detector=anomaly_detector,
    alert_manager=alert_manager
)

# -------------------------------------------------------------
# PROTECTED MOCK ENDPOINTS (Simulates downstream application APIs)
# -------------------------------------------------------------
@app.get("/api/v1/resource")
def get_resource():
    """
    Standard protected API resource.
    """
    return {
        "status": "success",
        "data": "This is a safe, high-value corporate resource accessed securely.",
        "server_time": os.popen("date").read().strip() if os.name != 'nt' else "2026-07-08T12:00:00"
    }

@app.post("/api/v1/auth/login")
async def mock_login(request: Request):
    """
    Mock authentication endpoint. Useful to test rate limiting, SQLi, and PII masking (passwords, tokens).
    """
    try:
        body = await request.json()
    except Exception:
        body = {}

    username = body.get("username", "anonymous")
    # Simulation: return a JWT token with masked outputs in audit logs
    return {
        "authenticated": True,
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy_secret_auth_token",
        "welcome": f"Hello, {username}!"
    }

@app.post("/api/v1/data/submit")
async def submit_data(request: Request):
    """
    Standard data entrypoint. Accepts customer information (tests PII scrubbing of CPFs, Credit Cards, Emails, etc.).
    """
    try:
        body = await request.json()
    except Exception:
        body = {}
    return {
        "status": "received",
        "processed_keys": list(body.keys()),
        "message": "Data securely processed and logged with sanitization filters."
    }

# -------------------------------------------------------------
# ADMINISTRATIVE CONTROL PLAN ENDPOINTS (Exempt from blocking)
# -------------------------------------------------------------
@app.get("/admin/dashboard", response_class=HTMLResponse)
def serve_dashboard(request: Request):
    """
    Renders the SOC interactive web interface.
    """
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/admin/metrics")
def get_system_metrics():
    """
    Returns live statistics.
    """
    return get_metrics()

@app.get("/admin/logs")
def get_system_logs(limit: int = Query(default=100, ge=1, le=500)):
    """
    Returns audit logs.
    """
    return get_audit_logs(limit=limit)

@app.get("/admin/blocklist")
def get_system_blocklist():
    """
    Returns active blocklist.
    """
    return get_active_blocks()

@app.post("/admin/blocklist")
def block_ip_address(ip: str = Form(...), duration: int = Form(300), reason: str = Form("Manual Block")):
    """
    Manually blacklists an IP address.
    """
    if not ip or len(ip.split('.')) != 4:
        raise HTTPException(status_code=400, detail="Invalid IP address format.")
    block_ip(ip, duration, reason)
    return {"message": f"IP {ip} successfully blacklisted for {duration} seconds."}

@app.post("/admin/blocklist/unblock")
def unblock_ip_address(ip: str = Query(...)):
    """
    Manually removes an IP from the blocklist.
    """
    unblock_ip(ip)
    return {"message": f"IP {ip} successfully unblocked."}

@app.post("/admin/config")
def update_system_config(
    mode: str = Form(...),
    rate_limit_requests_per_min: str = Form("100"),
    webhook_url: str = Form("")
):
    """
    Updates global gateway operations (Enforcement vs Audit-Only, Webhooks, and rate limiting).
    """
    if mode.lower() not in ["enforcement", "audit"]:
        raise HTTPException(status_code=400, detail="Invalid mode. Must be 'enforcement' or 'audit'.")

    set_config("mode", mode.lower())
    set_config("rate_limit_requests_per_min", rate_limit_requests_per_min)
    set_config("webhook_url", webhook_url)

    # Update live alert manager configuration
    alert_manager.update_webhook_url(webhook_url)

    logger.info(f"Global policy configurations updated: mode={mode}, rate_limit={rate_limit_requests_per_min}")
    return {"message": "Global system configurations saved successfully."}

@app.post("/admin/retrain")
def trigger_anomaly_retrain():
    """
    Triggers Isolation Forest online retraining with captured logs metadata.
    """
    # Fetch recent logs from DB to append to history
    logs = get_audit_logs(limit=200)

    # Process features from logs to append
    features_count = 0
    for l in logs:
        # Deduce query params count and payload size
        try:
            # Reconstruct attributes
            path = l["path"]
            query_count = len(path.split('?')[1].split('&')) if '?' in path else 0
            payload_size = len(l.get("sanitized_payload", "")) if l.get("sanitized_payload") else 0

            # Simple simulation of rate limit per log line
            rate_est = 20 if l["mitigation_action"] == "allowed" else 80

            anomaly_detector.history.append([
                float(len(path)),
                float(query_count),
                float(payload_size),
                float(rate_est)
            ])
            features_count += 1
        except Exception:
            pass

    anomaly_detector.trigger_retraining()
    return {
        "status": "triggered",
        "message": f"Online background retraining triggered with {features_count} additional threat features."
    }

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
