# Project 4: Application Security Demonstration Lab

An interactive laboratory demonstrating application-level vulnerabilities side-by-side with defensive secure coding controls.

## Modules Covered
1. **SQL Injection (SQLi)**: Concatenation vs. Parameterized Statements.
2. **Cross-Site Scripting (XSS)**: Unsanitized DOM injection vs. HTML Entity Encoding & Content-Security-Policy.
3. **Broken Access Control & IDOR**: Direct sequential ID access vs. Strict RBAC & account ownership validation.
4. **Command Injection**: Unchecked shell strings vs. Strict Regex Whitelisting and safe subprocess parameter arrays.

---

## 🚀 Quick Start

### 1. Web UI Dashboard & REST API
```bash
python app.py
```
Open `http://127.0.0.1:8004` in your browser.

### 2. Interactive CLI Tool
```bash
python cli.py
```
