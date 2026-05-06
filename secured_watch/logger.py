"""
logger.py — Audit Logging System for SecureDB Watch
Records every query attempt with metadata to audit_log.json.
"""

import json
import os
from datetime import datetime

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit_log.json")


def _load_logs():
    """Load all audit logs from the JSON store."""
    try:
        with open(LOG_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _save_logs(logs):
    """Persist audit logs to the JSON store."""
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)


def log_query(username, query, risk_status, execution_status, message=""):
    """
    Record a query execution attempt in the audit log.

    Args:
        username: The user who executed the query.
        query: The SQL query string.
        risk_status: SAFE, LOW, MEDIUM, HIGH, CRITICAL
        execution_status: SUCCESS, BLOCKED, ERROR
        message: Additional context/result message.
    """
    logs = _load_logs()

    entry = {
        "id": len(logs) + 1,
        "username": username,
        "query": query,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "risk_status": risk_status,
        "execution_status": execution_status,
        "message": message,
    }

    logs.insert(0, entry)  # Newest first
    _save_logs(logs)
    return entry


def get_logs(limit=100):
    """Return audit logs, sorted newest first, with optional limit."""
    logs = _load_logs()
    return logs[:limit]


def get_user_logs(username, limit=100):
    """Return audit logs for a specific user, sorted newest first."""
    logs = _load_logs()
    user_logs = [l for l in logs if l.get("username") == username]
    return user_logs[:limit]


def clear_logs():
    """Clear all audit logs."""
    _save_logs([])
    return {"success": True, "message": "Audit logs cleared."}


def get_log_stats():
    """Return summary statistics of the audit log."""
    logs = _load_logs()

    stats = {
        "total_queries": len(logs),
        "successful": sum(1 for l in logs if l.get("execution_status") == "SUCCESS"),
        "blocked": sum(1 for l in logs if l.get("execution_status") == "BLOCKED"),
        "errors": sum(1 for l in logs if l.get("execution_status") == "ERROR"),
        "risk_breakdown": {
            "SAFE": sum(1 for l in logs if l.get("risk_status") == "SAFE"),
            "LOW": sum(1 for l in logs if l.get("risk_status") == "LOW"),
            "MEDIUM": sum(1 for l in logs if l.get("risk_status") == "MEDIUM"),
            "HIGH": sum(1 for l in logs if l.get("risk_status") == "HIGH"),
            "CRITICAL": sum(1 for l in logs if l.get("risk_status") == "CRITICAL"),
        },
    }

    return stats
