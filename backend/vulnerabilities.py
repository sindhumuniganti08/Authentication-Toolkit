"""
Project 4: Application Security Demonstration Lab - Vulnerabilities & Remediation Engine
Demonstrates side-by-side execution of 4 core web application security concepts:
1. SQL Injection (Unsafe concatenation vs Parameterized Prepared Statements)
2. Cross-Site Scripting (XSS) (Reflected innerHTML vs HTML Entity Sanitization)
3. Broken Access Control / IDOR (Insecure direct object reference vs RBAC authorization)
4. Command Injection & Input Validation (Unchecked string formatting vs Whitelist regex & safe subprocess args)
"""

import sqlite3
import html
import re
from typing import Dict, Any, List

class AppSecLabEngine:
    def __init__(self):
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.create_db()

    def create_db(self):
        cursor = self.conn.cursor()
        cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, role TEXT, balance REAL)")
        cursor.execute("INSERT INTO users VALUES (1, 'alice', 'alice@company.org', 'Admin', 5000.0)")
        cursor.execute("INSERT INTO users VALUES (2, 'bob', 'bob@company.org', 'User', 150.0)")
        cursor.execute("INSERT INTO users VALUES (3, 'charlie', 'charlie@company.org', 'User', 350.0)")
        self.conn.commit()

    def demo_sqli(self, user_input: str) -> Dict[str, Any]:
        cursor = self.conn.cursor()
        vulnerable_query = f"SELECT id, username, email, role, balance FROM users WHERE username = '{user_input}'"
        vuln_results = []
        vuln_error = ""
        try:
            cursor.execute(vulnerable_query)
            vuln_results = [dict(zip(["id", "username", "email", "role", "balance"], row)) for row in cursor.fetchall()]
        except Exception as e:
            vuln_error = str(e)

        secure_query = "SELECT id, username, email, role, balance FROM users WHERE username = ?"
        sec_results = []
        sec_error = ""
        try:
            cursor.execute(secure_query, (user_input,))
            sec_results = [dict(zip(["id", "username", "email", "role", "balance"], row)) for row in cursor.fetchall()]
        except Exception as e:
            sec_error = str(e)

        return {
            "concept": "SQL Injection (SQLi)",
            "vulnerable": {
                "executed_query": vulnerable_query,
                "results": vuln_results,
                "error": vuln_error,
                "status": "Vulnerable to arbitrary SQL syntax injection" if len(vuln_results) > 1 or vuln_error else "Query executed"
            },
            "secure": {
                "executed_query": secure_query + f" WITH PARAMS ({user_input},)",
                "results": sec_results,
                "error": sec_error,
                "status": "Safely parameterized. Input treated strictly as literal string value."
            }
        }

    def demo_xss(self, user_input: str) -> Dict[str, Any]:
        vuln_output = f"<div class='user-comment'>{user_input}</div>"
        sanitized_input = html.escape(user_input)
        sec_output = f"<div class='user-comment'>{sanitized_input}</div>"
        xss_detected = bool(re.search(r'<script|onload|onerror|javascript:', user_input, re.IGNORECASE))

        return {
            "concept": "Cross-Site Scripting (XSS)",
            "vulnerable": {
                "rendered_html": vuln_output,
                "status": "Vulnerable: Executable HTML/JS tags rendered unsanitized in browser DOM!" if xss_detected else "Rendered raw"
            },
            "secure": {
                "rendered_html": sec_output,
                "sanitized_text": sanitized_input,
                "status": "Secure: Special HTML characters (<, >, &, \") safely converted to entity codes."
            }
        }

    def demo_idor(self, requested_user_id: int, current_logged_in_user_id: int, current_role: str) -> Dict[str, Any]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, username, email, role, balance FROM users WHERE id = ?", (requested_user_id,))
        row = cursor.fetchone()
        vuln_data = dict(zip(["id", "username", "email", "role", "balance"], row)) if row else None
        
        sec_data = None
        sec_status = ""
        if current_role == "Admin" or requested_user_id == current_logged_in_user_id:
            cursor.execute("SELECT id, username, email, role, balance FROM users WHERE id = ?", (requested_user_id,))
            row = cursor.fetchone()
            sec_data = dict(zip(["id", "username", "email", "role", "balance"], row)) if row else None
            sec_status = "Access Granted: User is account owner or Administrator."
        else:
            sec_status = "Access Denied 403 Forbidden: Account ownership check failed."

        return {
            "concept": "Insecure Direct Object Reference (IDOR)",
            "vulnerable": {
                "data": vuln_data,
                "status": "Vulnerable: Any user can access arbitrary user records by guessing sequential IDs!"
            },
            "secure": {
                "data": sec_data,
                "status": sec_status
            }
        }

    def demo_command_injection(self, target_domain: str) -> Dict[str, Any]:
        vuln_cmd = f"ping -c 1 {target_domain}"
        cmd_injection_risk = any(char in target_domain for char in [';', '&', '|', '`', '$', '\n'])
        DOMAIN_REGEX = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'
        is_valid_domain = bool(re.match(DOMAIN_REGEX, target_domain.strip()))
        
        sec_status = ""
        sec_cmd_args = []
        if is_valid_domain:
            sec_cmd_args = ["ping", "-c", "1", target_domain.strip()]
            sec_status = "Valid hostname validated via strict Whitelist Regex."
        else:
            sec_status = "Validation Failed: Input rejected due to disallowed shell characters/format."

        return {
            "concept": "Command Injection & Input Validation",
            "vulnerable": {
                "command_str": vuln_cmd,
                "status": "Vulnerable: Meta-characters allowed! Execution of chained shell commands possible." if cmd_injection_risk else "Raw command formed"
            },
            "secure": {
                "command_args": sec_cmd_args,
                "is_valid": is_valid_domain,
                "status": sec_status
            }
        }

appsec_engine = AppSecLabEngine()
