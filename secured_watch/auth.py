"""
auth.py — Authentication Module for SecureDB Watch
Handles user authentication against users.json store.
"""

import json
import os

USERS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.json")


def _load_users():
    """Load all users from the JSON store."""
    try:
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _save_users(users):
    """Persist users list to the JSON store."""
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def authenticate(username, password):
    """
    Authenticate a user by username and password.

    Returns:
        dict | None — User dict (without password) on success, None on failure.
    """
    users = _load_users()
    for user in users:
        if user["username"] == username and user["password"] == password:
            return {"username": user["username"], "role": user["role"]}
    return None


def get_all_users():
    """Return all users (passwords masked)."""
    users = _load_users()
    return [{"username": u["username"], "role": u["role"]} for u in users]


def add_user(username, password, role):
    """
    Add a new user.

    Returns:
        dict with success status and message.
    """
    users = _load_users()

    # Check for duplicate username
    for u in users:
        if u["username"] == username:
            return {"success": False, "message": f"User '{username}' already exists."}

    users.append({"username": username, "password": password, "role": role})
    _save_users(users)
    return {"success": True, "message": f"User '{username}' created successfully."}


def delete_user(username):
    """
    Delete a user by username.
    Admin account cannot be deleted.

    Returns:
        dict with success status and message.
    """
    if username == "admin":
        return {"success": False, "message": "Cannot delete the admin account."}

    users = _load_users()
    original_len = len(users)
    users = [u for u in users if u["username"] != username]

    if len(users) == original_len:
        return {"success": False, "message": f"User '{username}' not found."}

    _save_users(users)
    return {"success": True, "message": f"User '{username}' deleted successfully."}


def update_user(username, password=None, role=None):
    """
    Update an existing user's password and/or role.
    Admin role cannot be changed.

    Returns:
        dict with success status and message.
    """
    users = _load_users()
    found = False

    for u in users:
        if u["username"] == username:
            found = True
            if username == "admin" and role and role != "admin":
                return {"success": False, "message": "Cannot change admin's role."}
            if password:
                u["password"] = password
            if role:
                u["role"] = role
            break

    if not found:
        return {"success": False, "message": f"User '{username}' not found."}

    _save_users(users)
    return {"success": True, "message": f"User '{username}' updated successfully."}
