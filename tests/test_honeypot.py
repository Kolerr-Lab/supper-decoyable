"""
tests/test_honeypot.py

Unit and integration tests for the honeypot defense module.
Tests fast responses, request capture, IP blocking, and alert forwarding.
"""

import asyncio
import json
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from decoyable.defense.honeypot import (
    block_ip,
    capture_request,
    forward_alert,
    get_client_ip,
    process_attack_async,
    router,
)


class TestHoneypotEndpoints:
    """Test honeypot endpoint functionality."""

    def setup_method(self):
        """Set up test client."""
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)
        self.client = TestClient(app)

    def test_honeypot_generic_response_fast(self):
        """Test that honeypot endpoints return fast generic responses."""
        import time

        # Test various endpoints
        endpoints = [
            "/decoy/admin",
            "/decoy/api/v1/users",
            "/decoy/.env",
            "/decoy/backup.sql",
            "/decoy/config.json",
        ]

        for endpoint in endpoints:
            start_time = time.time()
            response = self.client.get(endpoint)
            response_time = (time.time() - start_time) * 1000

            # Should return 200 and be reasonably fast (< 50ms in test environment)
            assert response.status_code == 200
            assert (
                response_time < 50
            ), f"Response too slow: {response_time}ms for {endpoint}"

    def test_honeypot_content_types(self):
        """Test that honeypot returns appropriate content types."""
        test_cases = [
            ("/decoy/api/data.json", "application/json", "status"),
            ("/decoy/wsdl", "application/xml", "<?xml"),
            ("/decoy/admin/login", "text/html", "<html>"),
            ("/decoy/unknown", "text/plain", "Service available"),
        ]

        for endpoint, expected_type, content_check in test_cases:
            response = self.client.get(endpoint)
            assert response.status_code == 200
            assert response.headers["content-type"].startswith(expected_type)
            assert content_check in response.text

    def test_honeypot_status_endpoint(self):
        """Test honeypot status endpoint."""
        response = self.client.get("/decoy/status")
        assert response.status_code == 200

        data = response.json()
        assert "status" in data
        assert "decoy_ports" in data
        assert "security_endpoint" in data
        assert "timestamp" in data
        assert data["status"] == "active"

    @patch("decoyable.defense.honeypot.process_attack_async")
    def test_honeypot_background_processing(self, mock_process):
        """Test that honeypot triggers background processing."""
        response = self.client.get("/decoy/suspicious/endpoint")

        # Should return immediately
        assert response.status_code == 200

        # Should trigger background processing
        mock_process.assert_called_once()

    def test_honeypot_recent_logs_placeholder(self):
        """Test recent logs endpoint (placeholder implementation)."""
        response = self.client.get("/decoy/logs/recent")
        assert response.status_code == 200

        data = response.json()
        assert "logs" in data
        assert "limit" in data
        assert "message" in data


class TestRequestCapture:
    """Test request capture functionality."""

    @pytest.fixture
    def mock_request(self):
        """Create a mock FastAPI request."""
        request = Mock(spec=Request)
        request.method = "POST"
        request.url.path = "/decoy/malicious"
        request.headers = {
            "user-agent": "MaliciousBot/1.0",
            "content-type": "application/json",
            "x-forwarded-for": "192.168.1.100",
        }
        request.query_params = {"action": "hack"}
        request.client = Mock()
        request.client.host = "10.0.0.1"
        return request

    @pytest.mark.asyncio
    async def test_get_client_ip_x_forwarded_for(self, mock_request):
        """Test IP extraction with X-Forwarded-For header."""
        ip = get_client_ip(mock_request)
        assert ip == "192.168.1.100"

    @pytest.mark.asyncio
    async def test_get_client_ip_x_real_ip(self, mock_request):
        """Test IP extraction with X-Real-IP header."""
        mock_request.headers = {"x-real-ip": "203.0.113.1"}
        ip = get_client_ip(mock_request)
        assert ip == "203.0.113.1"

    @pytest.mark.asyncio
    async def test_get_client_ip_direct(self, mock_request):
        """Test IP extraction from direct client."""
        mock_request.headers = {}
        ip = get_client_ip(mock_request)
        assert ip == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_get_client_ip_unknown(self, mock_request):
        """Test IP extraction when no IP available."""
        mock_request.headers = {}
        mock_request.client = None
        ip = get_client_ip(mock_request)
        assert ip == "unknown"

    @pytest.mark.asyncio
    @patch("decoyable.defense.honeypot.get_client_ip", return_value="192.168.1.100")
    async def test_capture_request_full(self, mock_get_ip, mock_request):
        """Test full request capture."""
        # Mock body reading
        mock_request.body = AsyncMock(return_value=b'{"attack": "payload"}')

        attack_log = await capture_request(mock_request)

        assert attack_log.ip_address == "192.168.1.100"
        assert attack_log.method == "POST"
        assert attack_log.path == "/decoy/malicious"
        assert attack_log.user_agent == "MaliciousBot/1.0"
        assert attack_log.query_params == {"action": "hack"}
        assert attack_log.body == '{"attack": "payload"}'


class TestAlertForwarding:
    """Test alert forwarding functionality."""

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient")
    async def test_forward_alert_success(self, mock_client_class):
        """Test successful alert forwarding."""
        import os

        old_endpoint = os.environ.get("SECURITY_TEAM_ENDPOINT")
        os.environ["SECURITY_TEAM_ENDPOINT"] = "https://test-endpoint.com/alerts"

        try:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_client.post.return_value = mock_response
            mock_client_class.return_value.__aenter__.return_value = mock_client

            test_data = {"attack": "test", "severity": "high"}
            await forward_alert(test_data)

            # Verify the call was made
            mock_client.post.assert_called_once_with(
                "https://test-endpoint.com/alerts",
                json=test_data,
                headers={"Content-Type": "application/json"},
            )
        finally:
            if old_endpoint:
                os.environ["SECURITY_TEAM_ENDPOINT"] = old_endpoint
            else:
                os.environ.pop("SECURITY_TEAM_ENDPOINT", None)

    @pytest.mark.asyncio
    async def test_forward_alert_no_endpoint(self):
        """Test alert forwarding when no endpoint configured."""
        import os

        old_endpoint = os.environ.get("SECURITY_TEAM_ENDPOINT")
        if "SECURITY_TEAM_ENDPOINT" in os.environ:
            del os.environ["SECURITY_TEAM_ENDPOINT"]

        try:
            # Should not raise exception
            await forward_alert({"test": "data"})
        finally:
            if old_endpoint:
                os.environ["SECURITY_TEAM_ENDPOINT"] = old_endpoint


class TestIPBlocking:
    """Test IP blocking functionality."""

    @pytest.mark.asyncio
    @patch("asyncio.create_subprocess_exec")
    async def test_block_ip_success(self, mock_subprocess):
        """Test successful IP blocking."""
        mock_process = AsyncMock()
        mock_process.wait.return_value = 0  # Success
        mock_subprocess.return_value = mock_process

        await block_ip("192.168.1.100")

        # Verify iptables command was called
        mock_subprocess.assert_called_once()
        args, kwargs = mock_subprocess.call_args
        assert args == ("iptables", "-A", "INPUT", "-s", "192.168.1.100", "-j", "DROP")

    @pytest.mark.asyncio
    @patch("asyncio.create_subprocess_exec")
    async def test_block_ip_failure(self, mock_subprocess):
        """Test IP blocking failure handling."""
        mock_process = AsyncMock()
        mock_process.wait.return_value = 1  # Failure
        mock_subprocess.return_value = mock_process

        # Should not raise exception
        await block_ip("192.168.1.100")


class TestAttackProcessing:
    """Test attack processing workflow."""

    @pytest.mark.asyncio
    @patch("decoyable.defense.honeypot.capture_request")
    @patch("decoyable.defense.honeypot.analyze_attack_async")
    @patch("decoyable.defense.honeypot.forward_alert")
    @patch("decoyable.defense.honeypot.block_ip")
    async def test_process_attack_full_workflow(
        self, mock_block_ip, mock_forward_alert, mock_analyze, mock_capture
    ):
        """Test complete attack processing workflow."""
        # Mock request
        mock_request = Mock()

        # Mock captured data
        mock_attack_log = Mock()
        mock_attack_log.ip_address = "192.168.1.100"
        mock_attack_log.recommended_action = "block_ip"
        mock_capture.return_value = mock_attack_log

        # Mock analysis result
        mock_analysis = {
            "attack_type": "sqli",
            "confidence": 0.9,
            "recommended_action": "block_ip",
        }
        mock_analyze.return_value = mock_analysis

        await process_attack_async(mock_request)

        # Verify all steps were called
        mock_capture.assert_called_once_with(mock_request)
        mock_analyze.assert_called_once()
        mock_forward_alert.assert_called_once()
        mock_block_ip.assert_called_once_with("192.168.1.100")

    @pytest.mark.asyncio
    @patch("decoyable.defense.honeypot.capture_request")
    @patch("decoyable.defense.honeypot.analyze_attack_async")
    async def test_process_attack_no_blocking(self, mock_analyze, mock_capture):
        """Test attack processing without IP blocking."""
        mock_request = Mock()
        mock_attack_log = Mock()
        mock_attack_log.recommended_action = "monitor"
        mock_capture.return_value = mock_attack_log

        mock_analysis = {
            "attack_type": "reconnaissance",
            "confidence": 0.6,
            "recommended_action": "monitor",
        }
        mock_analyze.return_value = mock_analysis

        await process_attack_async(mock_request)

        # IP blocking should not be called
        # (This would be verified if we mocked block_ip)
