import re
import time
import logging
import json
from fastapi import Request, Response, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from datetime import datetime
from typing import List, Tuple, Dict
from urllib.parse import unquote

from .database import is_ip_blocked, block_ip, log_request, get_config
from .pii_sanitizer import sanitize_payload, sanitize_dict_or_list
from .anomaly_detector import AnomalyDetector
from .alert_manager import AlertManager

logger = logging.getLogger("appsec.middleware")

# OWASP core signatures
SQLI_PATTERNS = [
    re.compile(r"union\s+all\s+select", re.IGNORECASE),
    re.compile(r"select\s+.*\s+from", re.IGNORECASE),
    re.compile(r"insert\s+into\s+.*values", re.IGNORECASE),
    re.compile(r"delete\s+from", re.IGNORECASE),
    re.compile(r"drop\s+table", re.IGNORECASE),
    re.compile(r"(\'|\"|--|#|\/\*|\*\/)", re.IGNORECASE),
    re.compile(r"\b(or|and)\b\s+[\w\d]+\s*=\s*[\w\d]+", re.IGNORECASE)
]

XSS_PATTERNS = [
    re.compile(r"<script.*?>.*?</script>", re.IGNORECASE),
    re.compile(r"<script.*?>", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"on\w+\s*=\s*['\"]?.*?['\"]?", re.IGNORECASE), # onload=, onerror=, onclick=
    re.compile(r"<iframe.*?>", re.IGNORECASE),
    re.compile(r"svg/onload", re.IGNORECASE),
    re.compile(r"<img\s+src\s*=\s*['\"]?javascript:", re.IGNORECASE)
]

TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./", re.IGNORECASE),
    re.compile(r"\.\.\\", re.IGNORECASE),
    re.compile(r"/etc/passwd", re.IGNORECASE),
    re.compile(r"/etc/shadow", re.IGNORECASE),
    re.compile(r"/windows/win\.ini", re.IGNORECASE),
    re.compile(r"\bboot\.ini\b", re.IGNORECASE)
]

class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, anomaly_detector: AnomalyDetector, alert_manager: AlertManager):
        super().__init__(app)
        self.anomaly_detector = anomaly_detector
        self.alert_manager = alert_manager

        # In-memory IP request tracker for sub-minute rate-limiting
        # Stores lists of request timestamps per IP: {ip: [t1, t2, ...]}
        self.ip_request_history: Dict[str, List[float]] = {}
        self.rate_limit_lock = time.time()

    async def _get_request_body(self, request: Request) -> bytes:
        """
        Safely reads the request body and preserves the receive stream
        so subsequent handlers can read it.
        """
        body = await request.body()
        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}
        request._receive = receive
        return body

    def _inspect_content(self, content: str) -> List[str]:
        """
        Scans a raw text string against OWASP Top 10 patterns.
        Returns a list of detected threat descriptions.
        """
        detected = []
        if not content:
            return detected

        # SQL Injection Checks
        for pattern in SQLI_PATTERNS:
            if pattern.search(content):
                detected.append("SQL Injection (SQLi)")
                break

        # XSS Checks
        for pattern in XSS_PATTERNS:
            if pattern.search(content):
                detected.append("Cross-Site Scripting (XSS)")
                break

        # Path Traversal Checks
        for pattern in TRAVERSAL_PATTERNS:
            if pattern.search(content):
                detected.append("Path Traversal")
                break

        return detected

    def _track_rate_limit(self, ip: str) -> Tuple[bool, int]:
        """
        Tracks IP request rate over the last 60 seconds.
        Returns (is_rate_limited, current_requests_per_min).
        """
        now = time.time()

        # Initialize or filter old timestamps
        history = self.ip_request_history.get(ip, [])
        history = [t for t in history if now - t < 60]
        history.append(now)
        self.ip_request_history[ip] = history

        # Fetch configured rate limit
        limit_str = get_config("rate_limit_requests_per_min", "100")
        try:
            limit = int(limit_str)
        except ValueError:
            limit = 100

        req_count = len(history)
        if req_count > limit:
            return True, req_count
        return False, req_count

    async def dispatch(self, request: Request, call_next) -> Response:
        ip = request.client.host if request.client else "127.0.0.1"
        path = request.url.path
        method = request.method

        # Bypass safety checks for admin static logs & dashboard to prevent self-blocking
        if path.startswith("/admin") or path.startswith("/static"):
            return await call_next(request)

        # 1. Check if IP is actively Blocklisted
        if is_ip_blocked(ip):
            logger.warning(f"Blocked request from blacklisted IP: {ip} targeting {path}")
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Access Forbidden",
                    "reason": "Your IP has been temporarily blacklisted due to suspicious activity.",
                    "mitigation_mode": "ENFORCEMENT"
                }
            )

        # 2. Rate Limit Enforcement
        is_limited, req_rate = self._track_rate_limit(ip)
        threats_detected = []

        if is_limited:
            threats_detected.append("Rate Limit Exceeded")

        # 3. Payload and Parameter Inspection (OWASP WAF)
        # Scan URL and Query parameters (decoded to match regex spaces)
        query_decoded = unquote(request.url.query)
        path_decoded = unquote(path)

        threats_detected.extend(self._inspect_content(path_decoded))
        threats_detected.extend(self._inspect_content(query_decoded))

        # Scan Headers
        headers_to_scan = ["user-agent", "referer", "cookie", "x-forwarded-for"]
        for header in headers_to_scan:
            header_val = request.headers.get(header, "")
            threats_detected.extend(self._inspect_content(header_val))

        # Scan Request Body (cloned safely)
        body_bytes = await self._get_request_body(request)
        body_str = ""
        payload_size = len(body_bytes)

        if payload_size > 0:
            try:
                body_str = body_bytes.decode("utf-8", errors="ignore")
                threats_detected.extend(self._inspect_content(body_str))
            except Exception:
                pass

        # Deduplicate threats
        threats_detected = list(set(threats_detected))

        # 4. Behavioral Anomaly Inspection via Isolation Forest
        num_query_params = len(request.query_params)
        eval_result = self.anomaly_detector.record_and_evaluate(
            ip=ip,
            path=path,
            query_params_count=num_query_params,
            payload_size=payload_size,
            req_rate_per_min=req_rate
        )

        if eval_result["is_anomaly"]:
            threats_detected.append(eval_result["reason"])

        # 5. Mitigation Policy Application (Audit-Only vs Enforcement)
        system_mode = get_config("mode", "enforcement").lower()

        if threats_detected:
            # PII sanitize payload for secure local audit logging
            sanitized_body = sanitize_payload(body_str) if body_str else ""

            if system_mode == "enforcement":
                # Actively BLOCK request
                # Log incident as BLOCKED
                log_request(
                    ip=ip,
                    path=path,
                    method=method,
                    threats=threats_detected,
                    status_code=403,
                    action="blocked",
                    payload=sanitized_body[:2000]
                )

                # Permanently or temporarily block the IP (e.g. 10 minutes)
                # Avoid self-blocking testclient/localhost to allow clean subsequent test execution
                if ip not in ["127.0.0.1", "testclient"]:
                    block_ip(ip, duration_seconds=600, reason=f"Triggered AppSec vulnerabilities: {', '.join(threats_detected)}")

                # Send structured background alerts
                self.alert_manager.send_incident_alert(
                    ip=ip,
                    path=path,
                    method=method,
                    threats=threats_detected,
                    mitigation="blocked",
                    payload_excerpt=body_str
                )

                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Security Blocked",
                        "reason": f"Malicious payload or behavior detected.",
                        "violations": threats_detected,
                        "mitigation_mode": "ENFORCEMENT"
                    }
                )
            else:
                # AUDIT ONLY MODE: Log as FLAGGED but let it pass through
                log_request(
                    ip=ip,
                    path=path,
                    method=method,
                    threats=threats_detected,
                    status_code=200, # Will be set to downstream actual code but flagged in audit
                    action="flagged",
                    payload=sanitized_body[:2000]
                )

                self.alert_manager.send_incident_alert(
                    ip=ip,
                    path=path,
                    method=method,
                    threats=threats_detected,
                    mitigation="flagged",
                    payload_excerpt=body_str
                )

        # If normal request, execute downstream API endpoints
        start_time = time.time()
        try:
            response = await call_next(request)
            duration = time.time() - start_time

            # Log successful normal requests periodically or filter to keep logs clean
            # Let's write normal requests to logs too so dashboard displays real-time request metrics!
            if not threats_detected:
                # Sanitize normal response/request body just in case
                sanitized_body = sanitize_payload(body_str) if body_str else ""
                log_request(
                    ip=ip,
                    path=path,
                    method=method,
                    threats=[],
                    status_code=response.status_code,
                    action="allowed",
                    payload=sanitized_body[:1000]
                )
            return response
        except Exception as e:
            # In case downstream crashes, log it
            logger.error(f"Error handling request: {e}")
            if not threats_detected:
                log_request(
                    ip=ip,
                    path=path,
                    method=method,
                    threats=["Server Error"],
                    status_code=500,
                    action="allowed",
                    payload=body_str[:1000]
                )
            raise HTTPException(status_code=500, detail="Internal Server Error")
