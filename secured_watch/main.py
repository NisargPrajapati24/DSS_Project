# -*- coding: utf-8 -*-
"""
main.py -- CLI Interface for SecureDB Watch
Interactive terminal-based query interface with full security pipeline.
"""

import os
import sys

# Ensure local imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Force UTF-8 output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from database import init_db, execute_query
from auth import authenticate
from rbac import check_permission
from query_analyzer import analyze_query
from logger import log_query


def print_banner():
    """Display the SecureDB Watch CLI banner."""
    print("\n" + "=" * 60)
    print("  SecureDB Watch -- CLI Monitor")
    print("  Database Activity Monitoring & Auditing System")
    print("=" * 60)


def print_separator():
    print("-" * 60)


def color_risk(risk):
    """Return a colored risk indicator for terminal output."""
    colors = {
        "SAFE": "\033[92m",      # Green
        "LOW": "\033[93m",       # Yellow
        "MEDIUM": "\033[33m",    # Orange
        "HIGH": "\033[91m",      # Red
        "CRITICAL": "\033[95m",  # Magenta
    }
    reset = "\033[0m"
    color = colors.get(risk, "")
    return f"{color}[{risk}]{reset}"


def login_flow():
    """Handle user login via terminal."""
    print("\n[LOGIN REQUIRED]")
    print_separator()

    while True:
        username = input("  Username: ").strip()
        password = input("  Password: ").strip()

        if not username or not password:
            print("  [ERROR] Both fields are required.\n")
            continue

        user = authenticate(username, password)
        if user:
            print(f"\n  [OK] Welcome, {username}! (Role: {user['role']})")
            return user
        else:
            print("  [ERROR] Invalid credentials. Try again.\n")


def display_results(data):
    """Display query results in a formatted table."""
    if not data:
        print("  (No results)")
        return

    # Get column headers
    columns = list(data[0].keys())
    
    # Calculate column widths
    widths = {col: max(len(str(col)), max(len(str(row.get(col, ""))) for row in data)) for col in columns}

    # Print header
    header = " | ".join(str(col).ljust(widths[col]) for col in columns)
    print(f"  {header}")
    print(f"  {'-' * len(header)}")

    # Print rows
    for row in data:
        row_str = " | ".join(str(row.get(col, "")).ljust(widths[col]) for col in columns)
        print(f"  {row_str}")


def query_flow(user):
    """Main query input loop."""
    username = user["username"]
    role = user["role"]

    print(f"\n[Query Console] Logged in as: {username} | role: {role}")
    print("  Type SQL queries to execute. Type 'exit' to quit.\n")

    while True:
        print_separator()
        query = input("  SQL> ").strip()

        if not query:
            continue

        if query.lower() in ("exit", "quit", "q"):
            print("\n  Goodbye! Session ended.")
            break

        # Step 1: Analyze
        print("\n  [ANALYZE] Analyzing query...")
        analysis = analyze_query(query)
        print(f"     Risk: {color_risk(analysis['risk_status'])}")
        print(f"     Message: {analysis['analyzer_message']}")

        if not analysis["is_safe"]:
            if analysis.get("threats"):
                print("     Threats detected:")
                for t in analysis["threats"]:
                    print(f"       [!] {t['rule_name']} ({t['threat_level']})")

            log_query(username, query, analysis["risk_status"], "BLOCKED", analysis["analyzer_message"])
            print("\n  [BLOCKED] Query BLOCKED by security engine.")
            continue

        # Step 2: RBAC Check
        print("\n  [RBAC] Checking permissions...")
        permission = check_permission(role, query)
        print(f"     {permission['message']}")

        if not permission["allowed"]:
            log_query(username, query, "SAFE", "BLOCKED", permission["message"])
            print("\n  [BLOCKED] Query BLOCKED by RBAC.")
            continue

        # Step 3: Execute
        print("\n  [EXEC] Executing query...")
        result = execute_query(query)

        if result["success"]:
            print(f"  [OK] {result['message']}")
            if result.get("data"):
                print()
                display_results(result["data"])
            log_query(username, query, "SAFE", "SUCCESS", result["message"])
        else:
            print(f"  [ERROR] {result['message']}")
            log_query(username, query, "SAFE", "ERROR", result["message"])

        print()


def main():
    """Main entry point for the CLI."""
    print_banner()

    # Initialize database
    init_db()

    # Login
    user = login_flow()
    print_separator()

    # Enter query loop
    query_flow(user)


if __name__ == "__main__":
    main()
