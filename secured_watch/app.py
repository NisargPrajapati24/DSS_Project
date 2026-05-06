"""
app.py — Flask Web Application for SecureDB Watch
Serves the web dashboard and REST API endpoints.
"""

import os
import sys
from flask import Flask, request, jsonify, session, render_template, redirect, url_for
from functools import wraps

# Ensure local imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import init_db, execute_query
from auth import authenticate, get_all_users, add_user, delete_user, update_user
from rbac import check_permission, get_all_roles, add_role, update_role, delete_role
from query_analyzer import analyze_query, get_all_rules, add_rule, delete_rule, update_rule
from logger import log_query, get_logs, get_user_logs, clear_logs, get_log_stats

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()


# ── Decorators ───────────────────────────────────────────────────────────────

def login_required(f):
    """Decorator to require authentication for a route."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            if request.is_json or request.path.startswith("/api"):
                return jsonify({"success": False, "message": "Authentication required."}), 401
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Decorator to require admin role for a route."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return jsonify({"success": False, "message": "Authentication required."}), 401
        if session["user"].get("role") != "admin":
            return jsonify({"success": False, "message": "Admin access required."}), 403
        return f(*args, **kwargs)
    return decorated


# ── Page Routes ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the main dashboard page."""
    return render_template("index.html")


# ── Auth API ─────────────────────────────────────────────────────────────────

@app.route("/login", methods=["POST"])
def login():
    """Authenticate user and create session."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "No data provided."}), 400

        username = data.get("username", "").strip()
        password = data.get("password", "").strip()

        if not username or not password:
            return jsonify({"success": False, "message": "Username and password are required."}), 400

        user = authenticate(username, password)
        if user:
            session["user"] = user
            return jsonify({
                "success": True,
                "message": f"Welcome, {username}!",
                "user": user,
            })
        else:
            return jsonify({"success": False, "message": "Invalid credentials."}), 401
    except Exception as e:
        return jsonify({"success": False, "message": f"Login error: {str(e)}"}), 500


@app.route("/logout", methods=["POST"])
def logout():
    """Destroy user session."""
    session.pop("user", None)
    return jsonify({"success": True, "message": "Logged out successfully."})


@app.route("/api/session", methods=["GET"])
def get_session():
    """Check current session status."""
    if "user" in session:
        return jsonify({"logged_in": True, "user": session["user"]})
    return jsonify({"logged_in": False, "user": None})


# ── Query API ────────────────────────────────────────────────────────────────

@app.route("/api/query", methods=["POST"])
@login_required
def run_query():
    """
    Execute a SQL query through the security pipeline:
    1. Analyze query for threats
    2. Check RBAC permissions
    3. Execute if safe and authorized
    4. Log everything
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "No data provided."}), 400

        query = data.get("query", "").strip()
        if not query:
            return jsonify({"success": False, "message": "Query cannot be empty."}), 400

        user = session["user"]
        username = user["username"]
        role = user["role"]

        # Step 1: Analyze query for security threats
        analysis = analyze_query(query)

        if not analysis["is_safe"]:
            # Log blocked query
            log_query(
                username=username,
                query=query,
                risk_status=analysis["risk_status"],
                execution_status="BLOCKED",
                message=analysis["analyzer_message"],
            )
            return jsonify({
                "success": False,
                "message": analysis["analyzer_message"],
                "risk_status": analysis["risk_status"],
                "threats": analysis.get("threats", []),
                "execution_status": "BLOCKED",
            })

        # Step 2: RBAC permission check
        permission = check_permission(role, query)

        if not permission["allowed"]:
            # Log unauthorized query
            log_query(
                username=username,
                query=query,
                risk_status="SAFE",
                execution_status="BLOCKED",
                message=permission["message"],
            )
            return jsonify({
                "success": False,
                "message": permission["message"],
                "risk_status": "SAFE",
                "execution_status": "BLOCKED",
            })

        # Step 3: Execute the query
        result = execute_query(query)

        # Step 4: Log the execution
        exec_status = "SUCCESS" if result["success"] else "ERROR"
        log_query(
            username=username,
            query=query,
            risk_status="SAFE",
            execution_status=exec_status,
            message=result["message"],
        )

        return jsonify({
            "success": result["success"],
            "message": result["message"],
            "data": result.get("data"),
            "rows_affected": result.get("rows_affected", 0),
            "risk_status": "SAFE",
            "execution_status": exec_status,
        })

    except Exception as e:
        return jsonify({"success": False, "message": f"Server error: {str(e)}"}), 500


# ── Logs API ─────────────────────────────────────────────────────────────────

@app.route("/api/logs", methods=["GET"])
@admin_required
def api_get_logs():
    """Return audit logs (admin only)."""
    limit = request.args.get("limit", 100, type=int)
    logs = get_logs(limit)
    return jsonify({"success": True, "logs": logs})


@app.route("/api/logs/stats", methods=["GET"])
@admin_required
def api_get_log_stats():
    """Return audit log statistics (admin only)."""
    stats = get_log_stats()
    return jsonify({"success": True, "stats": stats})


@app.route("/api/logs/clear", methods=["POST"])
@admin_required
def api_clear_logs():
    """Clear all audit logs (admin only)."""
    result = clear_logs()
    return jsonify(result)


@app.route("/api/logs/me", methods=["GET"])
@login_required
def api_get_my_logs():
    """Return the current user's own audit logs."""
    username = session["user"]["username"]
    limit = request.args.get("limit", 100, type=int)
    logs = get_user_logs(username, limit)
    return jsonify({"success": True, "logs": logs})


# ── Users API ────────────────────────────────────────────────────────────────

@app.route("/api/users", methods=["GET"])
@admin_required
def api_get_users():
    """Return all users (admin only)."""
    users = get_all_users()
    return jsonify({"success": True, "users": users})


@app.route("/api/users", methods=["POST"])
@admin_required
def api_add_user():
    """Add a new user (admin only)."""
    try:
        data = request.get_json()
        username = data.get("username", "").strip()
        password = data.get("password", "").strip()
        role = data.get("role", "").strip()

        if not username or not password or not role:
            return jsonify({"success": False, "message": "All fields are required."}), 400

        result = add_user(username, password, role)
        status = 200 if result["success"] else 400
        return jsonify(result), status
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/users/<username>", methods=["PUT"])
@admin_required
def api_update_user(username):
    """Update a user (admin only)."""
    try:
        data = request.get_json()
        password = data.get("password", "").strip() or None
        role = data.get("role", "").strip() or None
        result = update_user(username, password=password, role=role)
        status = 200 if result["success"] else 400
        return jsonify(result), status
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/users/<username>", methods=["DELETE"])
@admin_required
def api_delete_user(username):
    """Delete a user (admin only)."""
    result = delete_user(username)
    status = 200 if result["success"] else 400
    return jsonify(result), status


# ── Roles API ────────────────────────────────────────────────────────────────

@app.route("/api/roles", methods=["GET"])
@admin_required
def api_get_roles():
    """Return all roles (admin only)."""
    roles = get_all_roles()
    return jsonify({"success": True, "roles": roles})


@app.route("/api/roles", methods=["POST"])
@admin_required
def api_add_role():
    """Add a new role (admin only)."""
    try:
        data = request.get_json()
        name = data.get("name", "").strip()
        allowed = data.get("allowed_commands", [])
        blocked = data.get("blocked_commands", [])

        if not name:
            return jsonify({"success": False, "message": "Role name is required."}), 400

        result = add_role(name, allowed, blocked)
        status = 200 if result["success"] else 400
        return jsonify(result), status
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/roles/<name>", methods=["PUT"])
@admin_required
def api_update_role(name):
    """Update a role (admin only)."""
    try:
        data = request.get_json()
        allowed = data.get("allowed_commands")
        blocked = data.get("blocked_commands")
        result = update_role(name, allowed_commands=allowed, blocked_commands=blocked)
        status = 200 if result["success"] else 400
        return jsonify(result), status
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/roles/<name>", methods=["DELETE"])
@admin_required
def api_delete_role(name):
    """Delete a role (admin only)."""
    result = delete_role(name)
    status = 200 if result["success"] else 400
    return jsonify(result), status


# ── Rules API ────────────────────────────────────────────────────────────────

@app.route("/api/rules", methods=["GET"])
@admin_required
def api_get_rules():
    """Return all custom rules (admin only)."""
    rules = get_all_rules()
    return jsonify({"success": True, "rules": rules})


@app.route("/api/rules", methods=["POST"])
@admin_required
def api_add_rule():
    """Add a new custom rule (admin only)."""
    try:
        data = request.get_json()
        name = data.get("name", "").strip()
        rule_type = data.get("type", "KEYWORD").strip()
        value = data.get("value", "").strip()
        threat_level = data.get("threat_level", "MEDIUM").strip()
        description = data.get("description", "").strip()

        if not name or not value:
            return jsonify({"success": False, "message": "Name and value are required."}), 400

        result = add_rule(name, rule_type, value, threat_level, description)
        status = 200 if result["success"] else 400
        return jsonify(result), status
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/rules/<name>", methods=["PUT"])
@admin_required
def api_update_rule(name):
    """Update a custom rule (admin only)."""
    try:
        data = request.get_json()
        result = update_rule(
            name,
            rule_type=data.get("type"),
            value=data.get("value"),
            threat_level=data.get("threat_level"),
            description=data.get("description"),
        )
        status = 200 if result["success"] else 400
        return jsonify(result), status
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route("/api/rules/<name>", methods=["DELETE"])
@admin_required
def api_delete_rule(name):
    """Delete a custom rule (admin only)."""
    result = delete_rule(name)
    status = 200 if result["success"] else 400
    return jsonify(result), status


# ── Main Entry Point ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    print("\n" + "=" * 60)
    print("  SecureDB Watch -- Web Dashboard")
    print("=" * 60)
    print("  Open: http://127.0.0.1:5000")
    print("=" * 60 + "\n")
    app.run(debug=True, host="127.0.0.1", port=5000)
