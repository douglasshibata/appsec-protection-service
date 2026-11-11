import sqlite3
import json
import os
from datetime import datetime, timedelta

DB_PATH = os.environ.get("APPSEC_DB_PATH", "appsec_security.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Audit logs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        path TEXT NOT NULL,
        method TEXT NOT NULL,
        threats_detected TEXT NOT NULL, -- JSON formatted array
        status_code INTEGER NOT NULL,
        mitigation_action TEXT NOT NULL, -- 'blocked', 'flagged', 'allowed'
        sanitized_payload TEXT
    )
    """)

    # IP blocklist table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ip_blocklist (
        ip_address TEXT PRIMARY KEY,
        blocked_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        reason TEXT NOT NULL
    )
    """)

    # System config table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS system_config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """)

    # Seed default configurations
    default_configs = [
        ("mode", "enforcement"),  # 'enforcement' or 'audit'
        ("rate_limit_requests_per_min", "100"),
        ("anomaly_score_threshold", "0.85"),
        ("webhook_url", "")
    ]

    for key, value in default_configs:
        cursor.execute("INSERT OR IGNORE INTO system_config (key, value) VALUES (?, ?)", (key, value))

    conn.commit()
    conn.close()

def log_request(ip: str, path: str, method: str, threats: list, status_code: int, action: str, payload: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = datetime.utcnow().isoformat()
    threats_json = json.dumps(threats)
    cursor.execute("""
    INSERT INTO audit_logs (timestamp, ip_address, path, method, threats_detected, status_code, mitigation_action, sanitized_payload)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, ip, path, method, threats_json, status_code, action, payload))
    conn.commit()
    conn.close()

def get_config(key: str, default: str = None) -> str:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM system_config WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row["value"]
    return default

def set_config(key: str, value: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO system_config (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()

def block_ip(ip: str, duration_seconds: int, reason: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    blocked_at = datetime.utcnow()
    expires_at = blocked_at + timedelta(seconds=duration_seconds)

    cursor.execute("""
    INSERT OR REPLACE INTO ip_blocklist (ip_address, blocked_at, expires_at, reason)
    VALUES (?, ?, ?, ?)
    """, (ip, blocked_at.isoformat(), expires_at.isoformat(), reason))
    conn.commit()
    conn.close()

def is_ip_blocked(ip: str) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT expires_at FROM ip_blocklist WHERE ip_address = ?", (ip,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False

    expires_at = datetime.fromisoformat(row["expires_at"])
    if datetime.utcnow() > expires_at:
        # Block has expired, clean up dynamically
        cursor.execute("DELETE FROM ip_blocklist WHERE ip_address = ?", (ip,))
        conn.commit()
        conn.close()
        return False

    conn.close()
    return True

def unblock_ip(ip: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM ip_blocklist WHERE ip_address = ?", (ip,))
    conn.commit()
    conn.close()

def get_active_blocks() -> list:
    conn = get_db_connection()
    cursor = conn.cursor()
    # First clean up any expired blocks
    cursor.execute("SELECT ip_address, expires_at FROM ip_blocklist")
    rows = cursor.fetchall()
    now = datetime.utcnow()
    expired_ips = []
    for r in rows:
        if now > datetime.fromisoformat(r["expires_at"]):
            expired_ips.append(r["ip_address"])

    if expired_ips:
        cursor.execute(f"DELETE FROM ip_blocklist WHERE ip_address IN ({','.join('?'*len(expired_ips))})", expired_ips)
        conn.commit()

    cursor.execute("SELECT ip_address, blocked_at, expires_at, reason FROM ip_blocklist ORDER BY blocked_at DESC")
    active_blocks = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return active_blocks

def get_audit_logs(limit: int = 100) -> list:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, timestamp, ip_address, path, method, threats_detected, status_code, mitigation_action, sanitized_payload
    FROM audit_logs
    ORDER BY id DESC LIMIT ?
    """, (limit,))
    logs = []
    for r in cursor.fetchall():
        d = dict(r)
        try:
            d["threats_detected"] = json.loads(d["threats_detected"])
        except Exception:
            d["threats_detected"] = []
        logs.append(d)
    conn.close()
    return logs

def get_metrics() -> dict:
    conn = get_db_connection()
    cursor = conn.cursor()

    # Total logs
    cursor.execute("SELECT COUNT(*) as total FROM audit_logs")
    total_inspected = cursor.fetchone()["total"]

    # Mitigation counts
    cursor.execute("SELECT mitigation_action, COUNT(*) as count FROM audit_logs GROUP BY mitigation_action")
    mitigation_counts = {"blocked": 0, "flagged": 0, "allowed": 0}
    for r in cursor.fetchall():
        action = r["mitigation_action"]
        if action in mitigation_counts:
            mitigation_counts[action] = r["count"]

    # Active blocklisted count
    cursor.execute("SELECT COUNT(*) as count FROM ip_blocklist")
    blocked_ips_count = cursor.fetchone()["count"]

    # Threat Breakdown
    cursor.execute("SELECT threats_detected FROM audit_logs")
    rows = cursor.fetchall()
    threat_breakdown = {
        "SQL Injection": 0,
        "Cross-Site Scripting (XSS)": 0,
        "Path Traversal": 0,
        "API Abuse / Anomaly": 0,
        "Rate Limit Exceeded": 0
    }

    for r in rows:
        try:
            threats = json.loads(r["threats_detected"])
            for t in threats:
                if t in threat_breakdown:
                    threat_breakdown[t] += 1
                else:
                    # Generic mapping or direct key
                    threat_breakdown[t] = threat_breakdown.get(t, 0) + 1
        except Exception:
            pass

    conn.close()

    return {
        "total_requests_inspected": total_inspected,
        "mitigation_actions": mitigation_counts,
        "active_blocked_ips": blocked_ips_count,
        "threat_breakdown": threat_breakdown,
        "system_mode": get_config("mode", "enforcement")
    }

# Initialize DB when imported
init_db()
