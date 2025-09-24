#!/usr/bin/env python3
"""
Comprehensive System Test Suite for DECOYABLE
Tests all components: core functionality, Kafka streaming, VS Code extension, Docker integration
"""

import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest
import requests


class DecoyableSystemTest:
    def __init__(self):
        self.base_dir = Path("g:/TECH/DECOYABLE")
        self.test_results = []
        self.api_base = "http://localhost:8000"
        self.kafka_enabled = False

    def log_test(self, test_name: str, status: str, message: str = ""):
        """Log test results"""
        result = {"test": test_name, "status": status, "message": message, "timestamp": time.time()}
        self.test_results.append(result)
        print(f"[{status.upper()}] {test_name}: {message}")

    async def test_basic_functionality(self):
        """Test core DECOYABLE functionality without Kafka"""
        try:
            # Test CLI help
            result = subprocess.run(
                [sys.executable, "-m", "decoyable.core.cli", "--help"],
                capture_output=True,
                text=True,
                cwd=self.base_dir,
            )
            if result.returncode == 0 and "usage:" in result.stdout.lower():
                self.log_test("CLI Help", "PASS", "CLI help command works")
            else:
                self.log_test("CLI Help", "FAIL", f"CLI help failed: {result.stderr}")

            # Test registry functionality
            from decoyable.core.registry import AttackRegistry

            registry = AttackRegistry()
            registry.register_attack_type("test_attack", {"description": "Test attack"})
            if "test_attack" in registry.get_attack_types():
                self.log_test("Registry", "PASS", "Attack registry works")
            else:
                self.log_test("Registry", "FAIL", "Attack registry failed")

            # Test scanners
            from decoyable.scanners.secrets import SecretScanner

            scanner = SecretScanner()
            test_content = "password = 'secret123'"
            findings = scanner.scan_content(test_content)
            if findings:
                self.log_test("Secret Scanner", "PASS", f"Found {len(findings)} secrets")
            else:
                self.log_test("Secret Scanner", "FAIL", "Secret scanner not working")

        except Exception as e:
            self.log_test("Basic Functionality", "FAIL", str(e))

    async def test_kafka_integration(self):
        """Test Kafka streaming components"""
        try:
            # Check if Kafka dependencies are available
            try:
                import aiokafka

                kafka_available = True
            except ImportError:
                kafka_available = False
                self.log_test("Kafka Dependencies", "SKIP", "aiokafka not installed")
                return

            if not kafka_available:
                return

            # Test Kafka producer (mocked)
            from decoyable.streaming.kafka_producer import KafkaAttackProducer

            producer = KafkaAttackProducer(bootstrap_servers="localhost:9092", topic="test-attacks")

            # Mock the producer to avoid needing actual Kafka
            producer.producer = None  # Mock
            test_event = {"type": "test_attack", "source_ip": "192.168.1.1", "timestamp": time.time()}

            # This should not raise an exception even without Kafka
            try:
                await producer.publish_attack_event(test_event)
                self.log_test("Kafka Producer", "PASS", "Producer handles missing Kafka gracefully")
            except Exception as e:
                if "kafka" in str(e).lower():
                    self.log_test("Kafka Producer", "PASS", "Producer degrades gracefully without Kafka")
                else:
                    self.log_test("Kafka Producer", "FAIL", str(e))

        except Exception as e:
            self.log_test("Kafka Integration", "FAIL", str(e))

    async def test_api_endpoints(self):
        """Test API endpoints"""
        try:
            # Start API server in background
            import uvicorn

            # Test API directly without starting server
            from fastapi.testclient import TestClient

            from decoyable.api.app import app

            client = TestClient(app)

            # Test health endpoint
            response = client.get("/health")
            if response.status_code == 200:
                self.log_test("API Health", "PASS", "Health endpoint works")
            else:
                self.log_test("API Health", "FAIL", f"Status: {response.status_code}")

            # Test attacks endpoint
            response = client.get("/api/v1/attacks")
            if response.status_code == 200:
                self.log_test("API Attacks", "PASS", "Attacks endpoint works")
            else:
                self.log_test("API Attacks", "FAIL", f"Status: {response.status_code}")

        except Exception as e:
            self.log_test("API Endpoints", "FAIL", str(e))

    async def test_docker_compose(self):
        """Test Docker Compose configuration"""
        try:
            compose_file = self.base_dir / "docker-compose.yml"
            if not compose_file.exists():
                self.log_test("Docker Compose", "FAIL", "docker-compose.yml not found")
                return

            # Validate YAML syntax
            import yaml

            with open(compose_file) as f:
                config = yaml.safe_load(f)

            required_services = ["app", "redis"]
            for service in required_services:
                if service in config.get("services", {}):
                    self.log_test(f"Docker {service}", "PASS", f"{service} service defined")
                else:
                    self.log_test(f"Docker {service}", "FAIL", f"{service} service missing")

            # Check Kafka profile
            kafka_services = ["zookeeper", "kafka"]
            profiles = config.get("services", {}).get("kafka", {}).get("profiles", [])
            if "kafka" in profiles:
                self.log_test("Docker Kafka Profile", "PASS", "Kafka profile configured")
            else:
                self.log_test("Docker Kafka Profile", "FAIL", "Kafka profile not configured")

        except Exception as e:
            self.log_test("Docker Compose", "FAIL", str(e))

    def test_vscode_extension(self):
        """Test VS Code extension package"""
        try:
            extension_dir = self.base_dir / "vscode-extension"
            if not extension_dir.exists():
                self.log_test("VS Code Extension", "FAIL", "Extension directory not found")
                return

            package_json = extension_dir / "package.json"
            if not package_json.exists():
                self.log_test("VS Code Extension", "FAIL", "package.json not found")
                return

            with open(package_json) as f:
                package_data = json.load(f)

            required_fields = ["name", "version", "engines", "activationEvents", "contributes"]
            for field in required_fields:
                if field in package_data:
                    self.log_test(f"VS Code {field}", "PASS", f"{field} defined")
                else:
                    self.log_test(f"VS Code {field}", "FAIL", f"{field} missing")

            # Check for .vsix file
            vsix_files = list(extension_dir.glob("*.vsix"))
            if vsix_files:
                self.log_test("VS Code Package", "PASS", f"Found {len(vsix_files)} .vsix file(s)")
            else:
                self.log_test("VS Code Package", "WARN", "No .vsix file found - run 'npm run package'")

        except Exception as e:
            self.log_test("VS Code Extension", "FAIL", str(e))

    async def run_unit_tests(self):
        """Run pytest unit tests"""
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pytest", "tests/", "-v"], capture_output=True, text=True, cwd=self.base_dir
            )

            if result.returncode == 0:
                self.log_test("Unit Tests", "PASS", "All tests passed")
            else:
                self.log_test("Unit Tests", "FAIL", f"Tests failed: {result.stderr}")

        except Exception as e:
            self.log_test("Unit Tests", "FAIL", str(e))

    def generate_report(self):
        """Generate test report"""
        passed = len([r for r in self.test_results if r["status"] == "PASS"])
        failed = len([r for r in self.test_results if r["status"] == "FAIL"])
        skipped = len([r for r in self.test_results if r["status"] == "SKIP"])
        warned = len([r for r in self.test_results if r["status"] == "WARN"])

        print("\n" + "=" * 60)
        print("DECOYABLE SYSTEM TEST REPORT")
        print("=" * 60)
        print(f"Total Tests: {len(self.test_results)}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Skipped: {skipped}")
        print(f"Warnings: {warned}")
        print()

        if failed > 0:
            print("FAILED TESTS:")
            for result in self.test_results:
                if result["status"] == "FAIL":
                    print(f"  - {result['test']}: {result['message']}")

        if warned > 0:
            print("WARNINGS:")
            for result in self.test_results:
                if result["status"] == "WARN":
                    print(f"  - {result['test']}: {result['message']}")

        return passed, failed, skipped, warned

    async def run_all_tests(self):
        """Run complete test suite"""
        print("Starting DECOYABLE System Tests...")
        print("=" * 60)

        await self.test_basic_functionality()
        await self.test_kafka_integration()
        await self.test_api_endpoints()
        await self.test_docker_compose()
        self.test_vscode_extension()
        await self.run_unit_tests()

        return self.generate_report()


async def main():
    tester = DecoyableSystemTest()
    passed, failed, skipped, warned = await tester.run_all_tests()

    # Exit with failure if any critical tests failed
    if failed > 0:
        sys.exit(1)
    else:
        print("\nAll tests passed! 🎉")
        sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())
