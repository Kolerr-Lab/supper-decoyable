"""
tests/test_analysis.py

Unit and integration tests for the LLM analysis and adaptive defense module.
Tests attack classification, knowledge base, and adaptive learning.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi.testclient import TestClient

from decoyable.defense.analysis import (
    AdaptiveDefense,
    KnowledgeBase,
    analyze_attack_async,
    analyze_attack_patterns,
    analyze_attack_with_llm,
    apply_adaptive_defense,
    get_llm_router,
)
from decoyable.llm import ProviderConfig, LLMRouter, OpenAIProvider


class TestKnowledgeBase:
    """Test knowledge base functionality."""

    def setup_method(self):
        """Set up temporary database for testing."""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()
        self.kb = KnowledgeBase(self.temp_db.name)

    def teardown_method(self):
        """Clean up temporary database."""
        try:
            Path(self.temp_db.name).unlink(missing_ok=True)
        except PermissionError:
            pass  # File still open on Windows, ignore

    def test_store_and_retrieve_analysis(self):
        """Test storing and retrieving attack analysis."""
        attack_data = {
            "method": "POST",
            "path": "/login",
            "ip_address": "192.168.1.100",
            "body": "user=admin&pass=' OR '1'='1",
        }

        analysis_result = {
            "attack_type": "sqli",
            "confidence": 0.95,
            "recommended_action": "block_ip",
        }

        # Store analysis
        attack_id = self.kb.store_analysis(attack_data, analysis_result)
        assert attack_id > 0

        # Retrieve recent analyses
        recent = self.kb.get_recent_analyses(limit=10)
        assert len(recent) == 1
        assert recent[0]["attack_data"] == attack_data
        assert recent[0]["analysis_result"] == analysis_result
        assert recent[0]["id"] == attack_id

    def test_attack_statistics(self):
        """Test attack statistics generation."""
        # Store multiple attacks
        attacks = [
            {"attack_type": "sqli", "severity": "high"},
            {"attack_type": "xss", "severity": "medium"},
            {"attack_type": "sqli", "severity": "high"},
            {"attack_type": "reconnaissance", "severity": "low"},
        ]

        for attack in attacks:
            self.kb.store_analysis({"test": "data"}, attack)

        # Get stats
        stats = self.kb.get_attack_stats(days=7)

        assert stats["total_attacks"] == 4
        assert stats["attack_types"]["sqli"] == 2
        assert stats["attack_types"]["xss"] == 1
        assert stats["attack_types"]["reconnaissance"] == 1

    def test_feedback_update(self):
        """Test updating feedback on analyses."""
        attack_data = {"test": "data"}
        analysis_result = {"attack_type": "unknown"}

        attack_id = self.kb.store_analysis(attack_data, analysis_result)

        # Update feedback
        success = self.kb.update_feedback(attack_id, "This was actually XSS")
        assert success

        # Verify feedback was stored
        recent = self.kb.get_recent_analyses(limit=1)
        assert recent[0]["feedback"] == "This was actually XSS"


class TestAdaptiveDefense:
    """Test adaptive defense functionality."""

    def setup_method(self):
        """Set up adaptive defense instance."""
        self.ad = AdaptiveDefense()

    def test_add_pattern(self):
        """Test adding dynamic patterns."""
        self.ad.add_pattern("sqli", r"UNION SELECT")
        assert "sqli" in self.ad.dynamic_patterns
        assert r"UNION SELECT" in self.ad.dynamic_patterns["sqli"]

    def test_block_ip(self):
        """Test IP blocking tracking."""
        self.ad.block_ip("192.168.1.100")
        assert "192.168.1.100" in self.ad.blocked_ips

    def test_add_decoy_endpoint(self):
        """Test decoy endpoint addition."""
        self.ad.add_decoy_endpoint("/api/graphql")
        assert "/api/graphql" in self.ad.decoy_endpoints

    def test_get_all_patterns(self):
        """Test combining static and dynamic patterns."""

        # Add dynamic pattern
        self.ad.add_pattern("custom", r"custom attack")

        all_patterns = self.ad.get_all_patterns()

        # Should include static patterns
        assert "sqli" in all_patterns
        assert "xss" in all_patterns

        # Should include dynamic patterns
        assert "custom" in all_patterns
        assert r"custom attack" in all_patterns["custom"]


class TestPatternAnalysis:
    """Test pattern-based attack analysis."""

    @pytest.mark.asyncio
    async def test_sqli_detection(self):
        """Test SQL injection pattern detection."""
        attack_data = {
            "method": "POST",
            "path": "/login",
            "body": "user=admin' OR '1'='1",
            "headers": {},
            "query_params": {},
        }

        result = await analyze_attack_patterns(attack_data)

        assert result["attack_type"] == "sqli"
        assert result["confidence"] > 0.5
        assert result["recommended_action"] in ["block_ip", "monitor"]

    @pytest.mark.asyncio
    async def test_xss_detection(self):
        """Test XSS pattern detection."""
        attack_data = {
            "method": "GET",
            "path": "/search",
            "query_params": {"q": "<script>alert('xss')</script>"},
            "headers": {},
            "body": None,
        }

        result = await analyze_attack_patterns(attack_data)

        assert result["attack_type"] == "xss"
        assert result["confidence"] >= 0.5

    @pytest.mark.asyncio
    async def test_reconnaissance_detection(self):
        """Test reconnaissance pattern detection."""
        attack_data = {
            "method": "GET",
            "path": "/.env",
            "headers": {"User-Agent": "sqlmap/1.6"},
            "query_params": {},
            "body": None,
        }

        result = await analyze_attack_patterns(attack_data)

        assert result["attack_type"] == "reconnaissance"
        assert result["recommended_action"] == "monitor"

    @pytest.mark.asyncio
    async def test_unknown_attack(self):
        """Test unknown attack classification."""
        attack_data = {
            "method": "GET",
            "path": "/health",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "query_params": {},
            "body": None,
        }

        result = await analyze_attack_patterns(attack_data)

        assert result["attack_type"] == "unknown"
        assert result["confidence"] < 0.5
        assert result["recommended_action"] == "log_only"


class TestLLMAnalysis:
    """Test LLM-powered analysis."""

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient")
    async def test_llm_analysis_success(self, mock_client_class):
        """Test successful LLM analysis."""
        import os

        old_key = os.environ.get("OPENAI_API_KEY")
        os.environ["OPENAI_API_KEY"] = "test-key"

        try:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "attack_type": "sqli",
                                    "confidence": 0.95,
                                    "recommended_action": "block_ip",
                                    "explanation": "SQL injection detected",
                                    "severity": "high",
                                    "indicators": ["UNION SELECT"],
                                }
                            )
                        }
                    }
                ]
            }
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            attack_data = {
                "method": "POST",
                "path": "/login",
                "body": "user=admin' OR '1'='1",
            }
            result = await analyze_attack_with_llm(attack_data)

            assert result["attack_type"] == "sqli"
            assert result["confidence"] == pytest.approx(0.95)
            assert result["recommended_action"] == "block_ip"

        finally:
            if old_key:
                os.environ["OPENAI_API_KEY"] = old_key
            else:
                os.environ.pop("OPENAI_API_KEY", None)

    @pytest.mark.asyncio
    async def test_llm_fallback_to_patterns(self):
        """Test LLM fallback to pattern analysis."""
        import os

        # Ensure no API key
        old_key = os.environ.get("OPENAI_API_KEY")
        if "OPENAI_API_KEY" in os.environ:
            del os.environ["OPENAI_API_KEY"]

        try:
            attack_data = {
                "method": "POST",
                "path": "/login",
                "body": "user=admin' OR '1'='1",
            }

            result = await analyze_attack_with_llm(attack_data)

            # Should fall back to pattern analysis
            assert "attack_type" in result
            assert "confidence" in result

        finally:
            if old_key:
                os.environ["OPENAI_API_KEY"] = old_key


class TestAdaptiveDefenseApplication:
    """Test adaptive defense application."""

    @pytest.mark.asyncio
    @patch("decoyable.defense.analysis.adaptive_defense")
    async def test_apply_adaptive_defense_high_confidence(self, mock_ad):
        """Test adaptive defense with high confidence attack."""
        attack_data = {
            "path": "/api/search?query=admin%27%20UNION%20SELECT%20username,password%20FROM%20users--",
            "ip_address": "192.168.1.100",
        }

        analysis_result = {
            "attack_type": "sqli",
            "confidence": 0.9,
            "recommended_action": "block_ip",
        }

        await apply_adaptive_defense(attack_data, analysis_result)

        # Should add pattern and block IP
        mock_ad.add_pattern.assert_called()
        mock_ad.block_ip.assert_called_with("192.168.1.100")

    @pytest.mark.asyncio
    @patch("decoyable.defense.analysis.adaptive_defense")
    async def test_apply_adaptive_defense_reconnaissance(self, mock_ad):
        """Test adaptive defense for reconnaissance."""
        attack_data = {"path": "/graphql", "method": "GET"}

        analysis_result = {
            "attack_type": "reconnaissance",
            "confidence": 0.7,
            "recommended_action": "monitor",
        }

        await apply_adaptive_defense(attack_data, analysis_result)

        # Should add decoy endpoint
        mock_ad.add_decoy_endpoint.assert_called()


class TestAnalysisIntegration:
    """Integration tests for analysis module."""

    @pytest.mark.asyncio
    @patch("decoyable.defense.analysis.analyze_attack_with_llm")
    @patch("decoyable.defense.analysis.knowledge_base")
    async def test_analyze_attack_async_full(self, mock_kb, mock_llm):
        """Test complete async analysis workflow."""
        # Mock LLM response
        mock_llm.return_value = {
            "attack_type": "sqli",
            "confidence": 0.9,
            "recommended_action": "block_ip",
        }

        # Mock knowledge base
        mock_kb.store_analysis.return_value = 123

        attack_data = {
            "method": "POST",
            "path": "/login",
            "ip_address": "192.168.1.100",
        }

        result = await analyze_attack_async(attack_data)

        # Verify LLM was called
        mock_llm.assert_called_once_with(attack_data)

        # Verify storage
        mock_kb.store_analysis.assert_called_once()

        # Verify result includes attack_id
        assert result["attack_id"] == 123
        assert result["attack_type"] == "sqli"


class TestAnalysisRouter:
    """Test analysis FastAPI router endpoints."""

    def setup_method(self):
        """Set up test client."""
        from fastapi import FastAPI

        from decoyable.defense.analysis import router

        app = FastAPI()
        app.include_router(router)
        self.client = TestClient(app)

    @patch("decoyable.defense.analysis.knowledge_base")
    def test_recent_analyses_endpoint(self, mock_kb):
        """Test recent analyses endpoint."""
        mock_kb.get_recent_analyses.return_value = [
            {
                "id": 1,
                "timestamp": "2025-01-01T00:00:00",
                "attack_data": {"test": "data"},
                "analysis_result": {"attack_type": "sqli"},
                "feedback": None,
            }
        ]

        response = self.client.get("/analysis/recent?limit=5")
        assert response.status_code == 200

        data = response.json()
        assert "analyses" in data
        assert "count" in data
        assert data["count"] == 1

    @patch("decoyable.defense.analysis.knowledge_base")
    def test_attack_stats_endpoint(self, mock_kb):
        """Test attack statistics endpoint."""
        mock_kb.get_attack_stats.return_value = {
            "total_attacks": 10,
            "attack_types": {"sqli": 5, "xss": 3},
        }

        response = self.client.get("/analysis/stats?days=7")
        assert response.status_code == 200

        data = response.json()
        assert data["total_attacks"] == 10
        assert data["attack_types"]["sqli"] == 5

    @patch("decoyable.defense.analysis.knowledge_base")
    def test_feedback_endpoint(self, mock_kb):
        """Test feedback update endpoint."""
        mock_kb.update_feedback.return_value = True

        response = self.client.post("/analysis/feedback/123", json={"feedback": "This was actually XSS"})
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True

    def test_patterns_endpoint(self):
        """Test patterns endpoint."""
        response = self.client.get("/analysis/patterns")
        assert response.status_code == 200

        data = response.json()
        assert "static_patterns" in data
        assert "dynamic_patterns" in data
        assert "blocked_ips" in data


class TestLLMRouting:
    """Test LLM routing and failover functionality."""

    def test_llm_router_initialization(self):
        """Test LLM router initialization with providers."""
        configs = [
            ProviderConfig(name="openai", api_key="test-key-1", priority=1),
            ProviderConfig(name="anthropic", api_key="test-key-2", priority=2),
        ]

        router = LLMRouter(configs, start_health_checks=False)

        assert len(router.providers) == 2
        assert "openai" in router.providers
        assert "anthropic" in router.providers
        assert router.providers["openai"].config.priority == 1
        assert router.providers["anthropic"].config.priority == 2

    @pytest.mark.asyncio
    @patch("decoyable.llm.providers.OpenAIProvider.generate_completion")
    async def test_successful_routing(self, mock_generate):
        """Test successful routing to healthy provider."""
        mock_generate.return_value = {"choices": [{"message": {"content": '{"attack_type": "sqli"}'}}]}

        configs = [ProviderConfig(name="openai", api_key="test-key", priority=1)]
        router = LLMRouter(configs, start_health_checks=False)

        response, provider = await router.generate_completion("Test prompt")

        assert provider == "openai"
        assert "choices" in response
        mock_generate.assert_called_once()

    @pytest.mark.asyncio
    @patch("decoyable.llm.providers.OpenAIProvider.generate_completion")
    async def test_failover_to_backup(self, mock_openai_generate):
        """Test failover when primary provider fails."""
        # Mock primary provider failure
        mock_openai_generate.side_effect = Exception("API Error")

        # Mock backup provider success
        with patch("decoyable.llm.providers.AnthropicProvider.generate_completion") as mock_anthropic:
            mock_anthropic.return_value = {"choices": [{"message": {"content": '{"attack_type": "xss"}'}}]}

            configs = [
                ProviderConfig(name="openai", api_key="test-key-1", priority=1),
                ProviderConfig(name="anthropic", api_key="test-key-2", priority=2),
            ]
            router = LLMRouter(configs, max_retries=3, start_health_checks=False)

            # Make OpenAI provider unhealthy by recording failures
            openai_provider = router.providers["openai"]
            for _ in range(5):  # Make it unhealthy
                openai_provider.record_failure(Exception("Simulated failure"))

            response, provider = await router.generate_completion("Test prompt")

            assert provider == "anthropic"
            assert "choices" in response
            mock_openai_generate.assert_not_called()  # Should not be called since provider is unhealthy
            mock_anthropic.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_providers_available(self):
        """Test behavior when no providers are available."""
        router = LLMRouter([], start_health_checks=False)  # No providers

        with pytest.raises(RuntimeError, match="No healthy LLM providers available"):
            await router.generate_completion("Test prompt")

    def test_provider_status_tracking(self):
        """Test provider status and metrics tracking."""
        config = ProviderConfig(name="openai", api_key="test-key", priority=1)
        provider = OpenAIProvider(config)

        # Initially healthy
        assert provider.is_healthy()

        # Record failure
        provider.record_failure(Exception("Test error"))
        assert provider.metrics.failed_requests == 1
        assert provider.metrics.consecutive_failures == 1

        # Record success
        provider.record_success(1.5)
        assert provider.metrics.successful_requests == 1
        assert provider.metrics.consecutive_failures == 0
        assert provider.metrics.total_latency == 1.5

    def test_router_status_endpoint(self):
        """Test router status endpoint."""
        configs = [ProviderConfig(name="openai", api_key="test-key", priority=1)]
        router = LLMRouter(configs, start_health_checks=False)

        status = router.get_provider_status()

        assert "openai" in status
        assert "status" in status["openai"]
        assert "metrics" in status["openai"]
        assert "config" in status["openai"]

    @pytest.mark.asyncio
    @patch("decoyable.defense.analysis.create_multi_provider_router")
    async def test_get_llm_router_function(self, mock_create_router):
        """Test get_llm_router function."""
        mock_router = Mock()
        mock_create_router.return_value = mock_router

        # Clear any existing router
        import decoyable.defense.analysis
        decoyable.defense.analysis._llm_router = None

        router = get_llm_router()

        assert router == mock_router
        mock_create_router.assert_called_once()


class TestLLMStatusEndpoint:
    """Test LLM status API endpoint."""

    def setup_method(self):
        """Set up test client."""
        from decoyable.api.app import app
        self.client = TestClient(app)

    def test_llm_status_endpoint(self):
        """Test LLM status API endpoint."""
        # Test with no router initialized
        import decoyable.defense.analysis
        decoyable.defense.analysis._llm_router = None

        response = self.client.get("/analysis/llm-status")
        assert response.status_code == 200

        data = response.json()
        assert "router_status" in data
        assert "providers" in data
        assert data["router_status"] == "inactive"
        assert data["providers"] == {}
