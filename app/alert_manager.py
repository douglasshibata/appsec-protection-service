import requests
import json
import logging
import threading
import uuid
from datetime import datetime
from typing import Dict, Any, List
from .pii_sanitizer import sanitize_payload

logger = logging.getLogger("appsec.alert_manager")

class AlertManager:
    def __init__(self, webhook_url: str = None):
        self.webhook_url = webhook_url

    def update_webhook_url(self, url: str):
        self.webhook_url = url

    def send_incident_alert(self, ip: str, path: str, method: str, threats: List[str], mitigation: str, payload_excerpt: str = None):
        """
        Formats and dispatches a detailed threat incident alert to configured channels.
        The execution runs in a background thread to prevent introducing latency to the core request loop.
        """
        incident_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat()

        # Sanitize payload before sending outside to guarantee absolute privacy
        sanitized_payload = sanitize_payload(payload_excerpt) if payload_excerpt else ""

        # Determine threat level
        threat_level = "CRITICAL" if mitigation == "blocked" else "WARNING"
        if not threats:
            threats = ["Unknown Anomaly"]

        incident_data = {
            "incident_id": incident_id,
            "timestamp": timestamp,
            "threat_level": threat_level,
            "mitigation_action": mitigation.upper(),
            "source_ip": ip,
            "endpoint": f"{method} {path}",
            "threats_detected": threats,
            "sanitized_payload_excerpt": sanitized_payload[:1000] # Limit size
        }

        # Log incident locally
        logger.warning(f"[INCIDENT-{incident_id}] AppSec Blocked/Flagged Threat! Detail: {json.dumps(incident_data)}")

        # Dispatch to Slack/Discord webhook asynchronously
        if self.webhook_url:
            threading.Thread(target=self._dispatch_webhook, args=(incident_data,), daemon=True).start()

    def _dispatch_webhook(self, incident_data: Dict[str, Any]):
        """
        Sends formatted markdown or JSON payload to Webhook.
        """
        headers = {"Content-Type": "application/json"}

        # Detect if it's a Slack or Discord webhook
        if "slack.com" in self.webhook_url or "discord.com" in self.webhook_url:
            # Format as a beautiful rich-text card block
            color = "#FF0000" if incident_data["threat_level"] == "CRITICAL" else "#FFA500"

            slack_payload = {
                "attachments": [
                    {
                        "fallback": f"AppSec Threat Detected: {', '.join(incident_data['threats_detected'])}",
                        "color": color,
                        "pretext": "🚨 *AppSec Real-Time Threat Mitigated!* 🚨",
                        "author_name": "AppSec Protection Engine",
                        "title": f"Incident {incident_data['incident_id']}",
                        "fields": [
                            {"title": "Source IP", "value": incident_data["source_ip"], "short": True},
                            {"title": "Endpoint", "value": incident_data["endpoint"], "short": True},
                            {"title": "Threat Level", "value": incident_data["threat_level"], "short": True},
                            {"title": "Mitigation", "value": incident_data["mitigation_action"], "short": True},
                            {"title": "Threats", "value": ", ".join(incident_data["threats_detected"]), "short": False},
                            {"title": "Sanitized Payload Excerpt", "value": f"```{incident_data['sanitized_payload_excerpt']}```", "short": False}
                        ],
                        "ts": int(datetime.utcnow().timestamp())
                    }
                ]
            }
            payload = slack_payload
        else:
            # Generic webhook structure
            payload = incident_data

        try:
            response = requests.post(self.webhook_url, json=payload, headers=headers, timeout=5)
            if response.status_code >= 400:
                logger.error(f"Webhook delivery failed with status code {response.status_code}: {response.text}")
        except Exception as e:
            logger.error(f"Failed to dispatch incident webhook: {e}")
