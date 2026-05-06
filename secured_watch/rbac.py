"""
rbac.py — Role-Based Access Control for SecureDB Watch
Validates queries against role permissions defined in roles.json.
"""

import json
import os
import re

ROLES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "roles.json")


def _load_roles():
    """Load all roles from the JSON store."""
    try:
        with open(ROLES_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _save_roles(roles):
    """Persist roles list to the JSON store."""
    with open(ROLES_FILE, "w") as f:
        json.dump(roles, f, indent=2)


def _extract_command(query):
    """
    Extract the primary SQL command from a query string.
    Returns the command keyword in uppercase (e.g., SELECT, INSERT, UPDATE, DELETE, DROP, ALTER).
    """
    query_clean = query.strip().upper()
    # Match the first SQL keyword
    match = re.match(r"^(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE)", query_clean)
    if match:
        return match.group(1)
    return None


def check_permission(role_name, query):
    """
    Check if a role has permission to execute the given query.

    Returns:
        dict with keys:
            - allowed (bool)
            - message (str)
    """
    roles = _load_roles()
    role = None

    for r in roles:
        if r["name"] == role_name:
            role = r
            break

    if role is None:
        return {
            "allowed": False,
            "message": f"Role '{role_name}' not found. Access denied.",
        }

    command = _extract_command(query)

    if command is None:
        return {
            "allowed": False,
            "message": "Could not determine SQL command type. Access denied.",
        }

    allowed_commands = [c.upper() for c in role.get("allowed_commands", [])]
    blocked_commands = [c.upper() for c in role.get("blocked_commands", [])]

    # Check if command is explicitly blocked
    if command in blocked_commands:
        return {
            "allowed": False,
            "message": f"Role '{role_name}' is blocked from executing {command} queries.",
        }

    # Check if ALL is allowed (and command isn't blocked above)
    if "ALL" in allowed_commands:
        return {
            "allowed": True,
            "message": f"Role '{role_name}' has ALL permissions. {command} allowed.",
        }

    # Check if specific command is allowed
    if command in allowed_commands:
        return {
            "allowed": True,
            "message": f"Role '{role_name}' is allowed to execute {command} queries.",
        }

    return {
        "allowed": False,
        "message": f"Role '{role_name}' does not have permission to execute {command} queries.",
    }


def get_all_roles():
    """Return all roles."""
    return _load_roles()


def add_role(name, allowed_commands, blocked_commands):
    """
    Add a new role.

    Returns:
        dict with success status and message.
    """
    roles = _load_roles()

    for r in roles:
        if r["name"] == name:
            return {"success": False, "message": f"Role '{name}' already exists."}

    roles.append({
        "name": name,
        "allowed_commands": allowed_commands,
        "blocked_commands": blocked_commands,
    })
    _save_roles(roles)
    return {"success": True, "message": f"Role '{name}' created successfully."}


def update_role(name, allowed_commands=None, blocked_commands=None):
    """
    Update an existing role's permissions.
    Admin role's allowed_commands cannot be changed.

    Returns:
        dict with success status and message.
    """
    roles = _load_roles()
    found = False

    for r in roles:
        if r["name"] == name:
            found = True
            if name == "admin":
                return {"success": False, "message": "Cannot modify the admin role."}
            if allowed_commands is not None:
                r["allowed_commands"] = allowed_commands
            if blocked_commands is not None:
                r["blocked_commands"] = blocked_commands
            break

    if not found:
        return {"success": False, "message": f"Role '{name}' not found."}

    _save_roles(roles)
    return {"success": True, "message": f"Role '{name}' updated successfully."}


def delete_role(name):
    """
    Delete a role by name.
    Admin role cannot be deleted.

    Returns:
        dict with success status and message.
    """
    if name == "admin":
        return {"success": False, "message": "Cannot delete the admin role."}

    roles = _load_roles()
    original_len = len(roles)
    roles = [r for r in roles if r["name"] != name]

    if len(roles) == original_len:
        return {"success": False, "message": f"Role '{name}' not found."}

    _save_roles(roles)
    return {"success": True, "message": f"Role '{name}' deleted successfully."}
