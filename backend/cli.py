"""
Project 4: Application Security Demonstration Lab - CLI Utility
"""

import sys
from backend.vulnerabilities import appsec_engine

def print_banner():
    print("=" * 65)
    print(" 🛡️  APPLICATION SECURITY DEMONSTRATION LAB (CLI) ")
    print("=" * 65)

def main():
    print_banner()
    while True:
        print("\nSelect Security Concept to Test:")
        print("1. SQL Injection (SQLi)")
        print("2. Cross-Site Scripting (XSS)")
        print("3. Broken Access Control (IDOR)")
        print("4. Command Injection & Input Validation")
        print("5. Exit")

        choice = input("\nChoice (1-5): ").strip()
        if choice == "1":
            inp = input("Enter search query vector [Default: admin' OR '1'='1]: ").strip() or "admin' OR '1'='1"
            res = appsec_engine.demo_sqli(inp)
            print(f"\n--- VULNERABLE RESULT ---")
            print(f"Status: {res['vulnerable']['status']}")
            print(f"Query:  {res['vulnerable']['executed_query']}")
            print(f"Data:   {res['vulnerable']['results']}")
            print(f"\n--- SECURE RESULT ---")
            print(f"Status: {res['secure']['status']}")
            print(f"Query:  {res['secure']['executed_query']}")
            print(f"Data:   {res['secure']['results']}")
            
        elif choice == "2":
            inp = input("Enter comment payload [Default: <script>alert(1)</script>]: ").strip() or "<script>alert(1)</script>"
            res = appsec_engine.demo_xss(inp)
            print(f"\n--- VULNERABLE RESULT ---")
            print(f"HTML:   {res['vulnerable']['rendered_html']}")
            print(f"\n--- SECURE RESULT ---")
            print(f"Status: {res['secure']['status']}")
            print(f"HTML:   {res['secure']['rendered_html']}")
            
        elif choice == "3":
            target_id = int(input("Target Account ID [Default: 1]: ").strip() or "1")
            my_id = int(input("My Account ID [Default: 2]: ").strip() or "2")
            role = input("My Role (User/Admin) [Default: User]: ").strip() or "User"
            res = appsec_engine.demo_idor(target_id, my_id, role)
            print(f"\n--- VULNERABLE RESULT ---")
            print(f"Status: {res['vulnerable']['status']}")
            print(f"Data:   {res['vulnerable']['data']}")
            print(f"\n--- SECURE RESULT ---")
            print(f"Status: {res['secure']['status']}")
            print(f"Data:   {res['secure']['data']}")

        elif choice == "4":
            inp = input("Enter target domain [Default: google.com; cat /etc/passwd]: ").strip() or "google.com; cat /etc/passwd"
            res = appsec_engine.demo_command_injection(inp)
            print(f"\n--- VULNERABLE RESULT ---")
            print(f"Command: {res['vulnerable']['command_str']}")
            print(f"Status:  {res['vulnerable']['status']}")
            print(f"\n--- SECURE RESULT ---")
            print(f"Status:  {res['secure']['status']}")
            print(f"Args:    {res['secure']['command_args']}")
            
        elif choice == "5":
            sys.exit(0)

if __name__ == "__main__":
    main()
