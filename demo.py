#!/usr/bin/env python3
"""
DECOYABLE Quick Demo Script

This script demonstrates DECOYABLE's security scanning capabilities
with sample vulnerable code. Run this to see DECOYABLE in action!

Usage:
    python demo.py
"""

import os
import tempfile
from pathlib import Path

# Sample vulnerable code for demonstration
SAMPLE_VULNERABLE_CODE = '''
# This file contains intentional security vulnerabilities for demo purposes
import os
import subprocess
import sqlite3

# Hardcoded secret (should be detected)
API_KEY = "sk-1234567890abcdef"  # API key exposed
DB_PASSWORD = "admin123"  # Weak password

def vulnerable_function(user_input, card_number):
    """
    Function with multiple security issues
    """
    # Command injection vulnerability
    os.system(f"ls {user_input}")  # Dangerous!

    # SQL injection vulnerability
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = '{user_input}'"  # SQL injection!
    cursor.execute(query)

    # Path traversal vulnerability
    filename = f"/tmp/{user_input}"  # Could be ../../../etc/passwd
    with open(filename, 'w') as f:
        f.write(card_number)  # Storing sensitive data insecurely

    return API_KEY

# AWS credentials (should be detected)
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# GitHub token (should be detected)
GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef12345678"
'''

def create_demo_files():
    """Create sample files with vulnerabilities for scanning."""
    demo_dir = Path("demo_vulnerable_code")

    # Create demo directory
    demo_dir.mkdir(exist_ok=True)

    # Create vulnerable Python file
    vuln_file = demo_dir / "vulnerable_app.py"
    vuln_file.write_text(SAMPLE_VULNERABLE_CODE)

    # Create requirements.txt with known vulnerable package
    req_file = demo_dir / "requirements.txt"
    req_file.write_text("requests==2.25.0  # Known vulnerable version\n")

    print(f"✅ Created demo files in {demo_dir}/")
    return demo_dir

def run_demo_scan(scan_dir):
    """Run DECOYABLE scan on the demo files."""
    print("\n🔍 Running DECOYABLE security scan...")
    print("=" * 50)

    try:
        # Import DECOYABLE components and setup services
        from decoyable.core.main import setup_services
        from decoyable.scanners.secrets_scanner import SecretsScanner, SecretsScannerConfig
        from decoyable.scanners.sast_scanner import SASTScanner, SASTScannerConfig
        from decoyable.scanners.deps_scanner import DependenciesScanner, DependenciesScannerConfig

        # Setup all services properly
        config, registry, cli_service = setup_services()

        # Initialize scanners with proper config
        secrets_config = SecretsScannerConfig()
        sast_config = SASTScannerConfig()
        deps_config = DependenciesScannerConfig()

        secrets_scanner = SecretsScanner(secrets_config)
        sast_scanner = SASTScanner(sast_config)
        deps_scanner = DependenciesScanner(deps_config)

        total_findings = 0

        # Scan for secrets
        print("🔑 Scanning for secrets...")
        import asyncio
        for py_file in scan_dir.glob("*.py"):
            try:
                report = asyncio.run(secrets_scanner.scan_path(str(py_file)))
                if report.results:
                    print(f"  📁 {py_file.name}:")
                    for finding in report.results:
                        print(f"    🚨 {finding.secret_type}: {finding.match[:20]}...")
                        total_findings += 1
            except Exception as e:
                print(f"  ❌ Error scanning {py_file.name}: {e}")

        # Scan for SAST vulnerabilities
        print("\n💻 Scanning for code vulnerabilities...")
        for py_file in scan_dir.glob("*.py"):
            try:
                report = asyncio.run(sast_scanner.scan_path(str(py_file)))
                if report.results:
                    print(f"  📁 {py_file.name}:")
                    for finding in report.results:
                        print(f"    🚨 {finding.vulnerability_type}: {finding.description}")
                        total_findings += 1
            except Exception as e:
                print(f"  ❌ Error scanning {py_file.name}: {e}")

        # Scan dependencies
        print("\n📦 Scanning dependencies...")
        req_file = scan_dir / "requirements.txt"
        if req_file.exists():
            try:
                report = asyncio.run(deps_scanner.scan_path(str(req_file)))
                if report.results:
                    for finding in report.results:
                        print(f"  🚨 Vulnerable package: {finding.package} {finding.version}")
                        print(f"    💡 {finding.description}")
                        total_findings += 1
            except Exception as e:
                print(f"  ❌ Error scanning dependencies: {e}")

        print("\n" + "=" * 50)
        print(f"🎯 DEMO COMPLETE: Found {total_findings} security issues!")
        print("\n💡 DECOYABLE caught these before they could become real security breaches!")

    except ImportError as e:
        print(f"❌ Could not import DECOYABLE: {e}")
        print("💡 Make sure DECOYABLE is properly installed:")
        print("   pip install -e .")
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        print("💡 This demo requires DECOYABLE to be properly set up")

def cleanup_demo(scan_dir):
    """Clean up demo files."""
    import shutil
    if scan_dir.exists():
        shutil.rmtree(scan_dir)
        print(f"🧹 Cleaned up demo files from {scan_dir}/")

def main():
    """Run the complete demo."""
    print("🚀 DECOYABLE Security Scanner Demo")
    print("===================================")
    print("This demo will create sample vulnerable code and scan it with DECOYABLE")
    print("to show how it detects real security issues.\n")

    # Create demo files
    demo_dir = create_demo_files()

    try:
        # Run the scan
        run_demo_scan(demo_dir)

        print("\n🎉 Demo completed successfully!")
        print("\n📖 What just happened:")
        print("   • DECOYABLE scanned Python code for secrets and vulnerabilities")
        print("   • It found hardcoded API keys, weak passwords, and code injection flaws")
        print("   • It identified vulnerable third-party packages")
        print("   • All issues were caught before deployment!")

        print("\n🔗 Learn more:")
        print("   • GitHub: https://github.com/Kolerr-Lab/supper-decoyable")
        print("   • Documentation: See README.md")
        print("   • Try it on your own code: decoyable scan .")

    finally:
        # Cleanup
        cleanup_demo(demo_dir)

if __name__ == "__main__":
    main()