"""
query_analyzer.py — Security Engine for SecureDB Watch
Detects SQL injection patterns, dangerous commands, and custom rules.
Returns threat assessment with risk levels.
"""

import json
import os
import re

RULES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.json")

# ── Built-in Detection Patterns ──────────────────────────────────────────────

# SQL Injection patterns
SQL_INJECTION_PATTERNS = [
    {
        "name": "OR 1=1 Injection",
        "pattern": r"(?i)\bOR\s+1\s*=\s*1\b",
        "threat_level": "CRITICAL",
        "description": "Classic SQL injection using OR 1=1 tautology.",
    },
    {
        "name": "OR True Injection",
        "pattern": r"(?i)\bOR\s+['\"]?\s*1\s*['\"]?\s*=\s*['\"]?\s*1\s*['\"]?",
        "threat_level": "CRITICAL",
        "description": "SQL injection with quoted tautology.",
    },
    {
        "name": "UNION SELECT Injection",
        "pattern": r"(?i)\bUNION\s+(ALL\s+)?SELECT\b",
        "threat_level": "CRITICAL",
        "description": "UNION-based SQL injection to extract data from other tables.",
    },
    {
        "name": "Comment Injection",
        "pattern": r"(--|#|/\*)",
        "threat_level": "HIGH",
        "description": "SQL comment injection to bypass query logic.",
    },
    {
        "name": "Stacked Query Injection",
        "pattern": r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE)",
        "threat_level": "CRITICAL",
        "description": "Stacked/chained query injection attempt.",
    },
    {
        "name": "String Escape Injection",
        "pattern": r"(?i)(\\'|\\\"|\%27|\%22)",
        "threat_level": "HIGH",
        "description": "String escape or encoding-based injection.",
    },
]

# Dangerous command patterns
DANGEROUS_COMMANDS = [
    {
        "name": "DROP Command",
        "pattern": r"(?i)^\s*DROP\b",
        "threat_level": "CRITICAL",
        "description": "DROP command can permanently destroy database objects.",
    },
    {
        "name": "DELETE without WHERE",
        "pattern": r"(?i)^\s*DELETE\s+FROM\s+\w+\s*$",
        "threat_level": "HIGH",
        "description": "DELETE without WHERE clause will remove all records.",
    },
    {
        "name": "ALTER Command",
        "pattern": r"(?i)^\s*ALTER\b",
        "threat_level": "HIGH",
        "description": "ALTER command can modify database structure.",
    },
    {
        "name": "TRUNCATE Command",
        "pattern": r"(?i)^\s*TRUNCATE\b",
        "threat_level": "CRITICAL",
        "description": "TRUNCATE will remove all data from a table.",
    },
]


def _load_custom_rules():
    """Load custom detection rules from rules.json."""
    try:
        with open(RULES_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _save_custom_rules(rules):
    """Persist custom rules to rules.json."""
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=2)


def _check_pattern(query, pattern_info):
    """Check a single pattern against the query."""
    try:
        if re.search(pattern_info["pattern"], query):
            return {
                "matched": True,
                "rule_name": pattern_info["name"],
                "threat_level": pattern_info["threat_level"],
                "description": pattern_info["description"],
            }
    except re.error:
        pass
    return {"matched": False}


def analyze_query(query):
    """
    Analyze a SQL query for security threats.

    Returns:
        dict with keys:
            - is_safe (bool)
            - risk_status (str): SAFE, LOW, MEDIUM, HIGH, CRITICAL
            - analyzer_message (str)
            - threats (list[dict]): List of detected threats
    """
    if not query or not query.strip():
        return {
            "is_safe": False,
            "risk_status": "LOW",
            "analyzer_message": "Empty query provided.",
            "threats": [],
        }

    threats = []
    query_stripped = query.strip()

    # Check SQL injection patterns
    for pattern in SQL_INJECTION_PATTERNS:
        result = _check_pattern(query_stripped, pattern)
        if result["matched"]:
            threats.append(result)

    # Check dangerous commands
    for pattern in DANGEROUS_COMMANDS:
        result = _check_pattern(query_stripped, pattern)
        if result["matched"]:
            threats.append(result)

    # Check custom rules from rules.json
    custom_rules = _load_custom_rules()
    for rule in custom_rules:
        rule_type = rule.get("type", "KEYWORD").upper()
        value = rule.get("value", "")
        threat_level = rule.get("threat_level", "MEDIUM")
        name = rule.get("name", "Custom Rule")
        description = rule.get("description", "Custom security rule triggered.")

        if rule_type == "KEYWORD":
            if value.upper() in query_stripped.upper():
                threats.append({
                    "matched": True,
                    "rule_name": name,
                    "threat_level": threat_level,
                    "description": description,
                })
        elif rule_type == "REGEX":
            try:
                if re.search(value, query_stripped, re.IGNORECASE):
                    threats.append({
                        "matched": True,
                        "rule_name": name,
                        "threat_level": threat_level,
                        "description": description,
                    })
            except re.error:
                pass

    # Determine overall risk
    if not threats:
        return {
            "is_safe": True,
            "risk_status": "SAFE",
            "analyzer_message": "Query passed all security checks.",
            "threats": [],
        }

    # Get highest threat level
    threat_hierarchy = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    max_level = max(threat_hierarchy.get(t["threat_level"], 0) for t in threats)
    risk_map = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
    risk_status = risk_map.get(max_level, "MEDIUM")

    threat_names = ", ".join(t["rule_name"] for t in threats)

    return {
        "is_safe": False,
        "risk_status": risk_status,
        "analyzer_message": f"[WARNING] Threats detected: {threat_names}",
        "threats": threats,
    }


# ── Custom Rules CRUD ────────────────────────────────────────────────────────

def get_all_rules():
    """Return all custom rules."""
    return _load_custom_rules()


def add_rule(name, rule_type, value, threat_level, description=""):
    """
    Add a custom detection rule.

    Args:
        name: Rule name
        rule_type: KEYWORD or REGEX
        value: The keyword or regex pattern
        threat_level: SAFE, LOW, MEDIUM, HIGH, CRITICAL
        description: Optional description

    Returns:
        dict with success status and message.
    """
    valid_types = ["KEYWORD", "REGEX"]
    valid_levels = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    if rule_type.upper() not in valid_types:
        return {"success": False, "message": f"Invalid rule type. Must be one of: {valid_types}"}

    if threat_level.upper() not in valid_levels:
        return {"success": False, "message": f"Invalid threat level. Must be one of: {valid_levels}"}

    # Validate regex if applicable
    if rule_type.upper() == "REGEX":
        try:
            re.compile(value)
        except re.error as e:
            return {"success": False, "message": f"Invalid regex pattern: {str(e)}"}

    rules = _load_custom_rules()

    for r in rules:
        if r.get("name") == name:
            return {"success": False, "message": f"Rule '{name}' already exists."}

    rules.append({
        "name": name,
        "type": rule_type.upper(),
        "value": value,
        "threat_level": threat_level.upper(),
        "description": description or f"Custom {rule_type} rule: {name}",
    })

    _save_custom_rules(rules)
    return {"success": True, "message": f"Rule '{name}' created successfully."}


def delete_rule(name):
    """
    Delete a custom rule by name.

    Returns:
        dict with success status and message.
    """
    rules = _load_custom_rules()
    original_len = len(rules)
    rules = [r for r in rules if r.get("name") != name]

    if len(rules) == original_len:
        return {"success": False, "message": f"Rule '{name}' not found."}

    _save_custom_rules(rules)
    return {"success": True, "message": f"Rule '{name}' deleted successfully."}


def update_rule(name, rule_type=None, value=None, threat_level=None, description=None):
    """
    Update an existing custom rule.

    Returns:
        dict with success status and message.
    """
    rules = _load_custom_rules()
    found = False

    for r in rules:
        if r.get("name") == name:
            found = True
            if rule_type:
                r["type"] = rule_type.upper()
            if value:
                r["value"] = value
            if threat_level:
                r["threat_level"] = threat_level.upper()
            if description:
                r["description"] = description
            break

    if not found:
        return {"success": False, "message": f"Rule '{name}' not found."}

    _save_custom_rules(rules)
    return {"success": True, "message": f"Rule '{name}' updated successfully."}
