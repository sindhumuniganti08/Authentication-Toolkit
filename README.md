# 🛡️ Cybersecurity Authentication Toolkit

A prototype demonstrating secure user authentication, password validation, salted password hashing, JWT session management, TOTP Multi-Factor Authentication (MFA), and rate-limiting security controls.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?style=for-the-badge&logo=fastapi)
![Security](https://img.shields.io/badge/Security-Bcrypt%20%26%20JWT-red?style=for-the-badge)

---

## 📌 Project Overview

The **Cybersecurity Authentication Toolkit** demonstrates defense-in-depth security principles for user identity and session lifecycle management. It enforces strict password complexity rules, cryptographically secure password storage, protection against brute-force attacks, multi-factor authentication, and centralized audit logging.

---

## ✨ Core Features & Security Controls

- **Password Strength & Entropy Analyzer**: Calculates Shannon entropy bits, evaluates character diversity (uppercase, lowercase, numbers, special characters), length requirements (minimum 12 characters), and checks against common weak password dictionaries.
- **Secure Password Storage (Bcrypt)**: Passwords are salted with a 128-bit cryptographically random salt and hashed using Bcrypt (cost factor 12). Plaintext passwords are never stored.
- **Account Lockout Protection**: Automatically locks accounts for 5 minutes (300 seconds) after 5 consecutive failed login attempts to prevent automated brute-force attacks.
- **Sliding-Window Rate Limiter**: Restricts sensitive authentication endpoints to a maximum of 10 requests per minute per IP address.
- **JWT Session Management**: Issues cryptographically signed JSON Web Tokens (HS256) with short-lived access tokens (15 mins) and long-lived refresh tokens.
- **TOTP Multi-Factor Authentication (RFC 6238)**: Supports 6-digit Time-based One-Time Password generation and verification with clock skew tolerance.
- **Security Audit Event Log**: Real-time tracking of security events (Registration, Authentication, Lockout, MFA) with client IP addresses, status badges, and timestamps.

---

## 📁 Project Directory Structure

```text
project-1-auth-toolkit/
├── auth_service.py     # Core authentication, Bcrypt, JWT, TOTP & Audit Logger logic
├── app.py              # FastAPI REST API server & Web Dashboard launcher
├── cli.py              # Interactive Command-Line Interface (CLI) testing tool
├── static/
│   └── index.html      # Dark-themed Web UI Dashboard
├── package.json        # Project metadata & script definitions
├── .gitignore          # Excludes virtual environments, secrets, and temp files
└── README.md           # Documentation
