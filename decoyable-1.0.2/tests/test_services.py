"""
tests/test_services.py

Comprehensive test suite for the service-based architecture.
Tests service initialization, dependency injection, registry integration,
and enterprise-grade validation.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from decoyable.core.config import Settings
from decoyable.core.registry import ServiceRegistry


class TestServiceRegistry:
    """Test service registry functionality."""

    def test_registry_initialization(self):
        """Test that service registry initializes correctly."""
        registry = ServiceRegistry("test-registry")
        assert registry._name == "test-registry"
        assert isinstance(registry._services, dict)
        assert isinstance(registry._instances, dict)

    def test_register_instance(self):
        """Test registering service instances."""
        registry = ServiceRegistry()
        test_service = Mock()
        test_service.name = "test"

        registry.register_instance("test_service", test_service)

        # Should be able to retrieve the instance
        retrieved = registry.get_by_name("test_service")
        assert retrieved is test_service

    def test_service_dependencies(self):
        """Test service dependency resolution."""
        registry = ServiceRegistry()

        # Register a mock config service
        config_mock = Mock()
        config_mock.database_url = "sqlite:///:memory:"
        registry.register_instance("config", config_mock)

        # Register a service that depends on config
        class TestService:
            def __init__(self, config):
                self.config = config

        registry.register_instance("test_service", TestService(config_mock))

        # Verify dependency injection
        service = registry.get_by_name("test_service")
        assert service.config is config_mock
        assert service.config.database_url == "sqlite:///:memory:"


class TestServiceInitialization:
    """Test service initialization and startup."""

    @patch("decoyable.scanners.service.ScannerService")
    @patch("decoyable.core.database_service.DatabaseService")
    @patch("decoyable.core.task_queue_service.TaskQueueService")
    @patch("decoyable.core.streaming_service.StreamingService")
    @patch("decoyable.core.cache_service.CacheService")
    def test_all_services_initialize(
        self, cache_mock, streaming_mock, task_queue_mock, database_service_mock, scanner_service_mock
    ):
        """Test that all core services can be initialized."""
        from decoyable.core.main import setup_services

        # Mock all service classes
        cache_mock.return_value = Mock()
        streaming_mock.return_value = Mock()
        task_queue_mock.return_value = Mock()
        database_service_mock.return_value = Mock()
        scanner_service_mock.return_value = Mock()

        # Initialize services
        config, registry, cli_service = setup_services()

        # Verify services are registered
        assert registry.get_by_name("config") is config
        assert registry.get_by_name("registry") is registry
        assert registry.get_by_name("cli_service") is cli_service

        # Verify service mocks were called
        cache_mock.assert_called_once()
        streaming_mock.assert_called_once()
        task_queue_mock.assert_called_once()
        database_service_mock.assert_called_once()

    def test_graceful_service_degradation(self):
        """Test that services degrade gracefully when dependencies are missing."""
        from decoyable.core.main import setup_services

        # This should not raise exceptions even if some services fail to initialize
        config, registry, cli_service = setup_services()

        # Core services should still be available
        assert registry.get_by_name("config") is config
        assert registry.get_by_name("registry") is registry
        assert registry.get_by_name("cli_service") is cli_service


class TestStreamingService:
    """Test streaming service functionality."""

    @pytest.fixture
    def registry(self):
        """Create a test registry."""
        return ServiceRegistry()

    @pytest.fixture
    def config(self):
        """Create a test config."""
        # Set environment variable to disable Kafka
        import os

        old_value = os.environ.get("KAFKA_ENABLED")
        os.environ["KAFKA_ENABLED"] = "false"

        config = Settings()

        # Restore environment variable
        if old_value is None:
            os.environ.pop("KAFKA_ENABLED", None)
        else:
            os.environ["KAFKA_ENABLED"] = old_value

        return config

    def test_streaming_service_initialization(self, registry, config):
        """Test streaming service initializes correctly."""
        from decoyable.core.streaming_service import StreamingService

        # Register dependencies
        registry.register_instance("config", config)
        registry.register_instance("database_service", Mock())
        registry.register_instance("cache_service", Mock())

        service = StreamingService(registry)

        # Should initialize without errors
        assert not service._initialized
        assert service.producer is None
        assert len(service.consumers) == 0

    @pytest.mark.asyncio
    async def test_streaming_service_async_init(self, registry, config):
        """Test async initialization of streaming service."""
        from decoyable.core.streaming_service import StreamingService

        # Register dependencies
        registry.register_instance("config", config)
        registry.register_instance("database_service", Mock())
        registry.register_instance("cache_service", Mock())

        service = StreamingService(registry)
        await service.initialize()

        assert service._initialized
        assert service.config is config

    @pytest.mark.asyncio
    async def test_publish_event_without_kafka(self, registry, config):
        """Test event publishing when Kafka is disabled."""
        from decoyable.core.streaming_service import StreamingService

        # Register dependencies
        registry.register_instance("config", config)
        registry.register_instance("database_service", Mock())
        registry.register_instance("cache_service", Mock())

        service = StreamingService(registry)
        await service.initialize()

        # Publishing should succeed even without Kafka
        success = await service.publish_attack_event("test_event", {"test": "data"}, key="test_key")

        # Should return False since producer is disabled
        assert success is False

    @pytest.mark.asyncio
    async def test_security_alert_publishing(self, registry, config):
        """Test security alert publishing."""
        from decoyable.core.streaming_service import StreamingService

        # Register dependencies
        registry.register_instance("config", config)
        registry.register_instance("database_service", Mock())
        registry.register_instance("cache_service", Mock())

        service = StreamingService(registry)
        await service.initialize()

        # Publishing alert should work
        success = await service.publish_security_alert(
            alert_type="test_alert", severity="high", message="Test security alert", source_ip="192.168.1.1"
        )

        assert success is False  # Kafka disabled

    @pytest.mark.asyncio
    async def test_streaming_status(self, registry, config):
        """Test streaming service status reporting."""
        from decoyable.core.streaming_service import StreamingService

        # Register dependencies
        registry.register_instance("config", config)
        registry.register_instance("database_service", Mock())
        registry.register_instance("cache_service", Mock())

        service = StreamingService(registry)
        await service.initialize()

        status = await service.get_streaming_stats()

        assert "service_available" in status
        assert "kafka_available" in status
        assert "producer_enabled" in status
        assert status["producer_enabled"] is False

    @pytest.mark.asyncio
    async def test_health_check(self, registry, config):
        """Test streaming service health checks."""
        from decoyable.core.streaming_service import StreamingService

        # Register dependencies
        registry.register_instance("config", config)
        registry.register_instance("database_service", Mock())
        registry.register_instance("cache_service", Mock())

        service = StreamingService(registry)
        await service.initialize()

        health = await service.health_check()

        assert "streaming_service" in health
        assert "producer" in health
        assert health["streaming_service"] == "healthy"
        assert health["producer"] == "disabled"


class TestHoneypotService:
    """Test honeypot service functionality."""

    @pytest.fixture
    def registry(self):
        """Create a test registry."""
        return ServiceRegistry()

    @pytest.fixture
    def config(self):
        """Create a test config."""
        config = Settings()
        return config

    def test_honeypot_service_initialization(self, registry, config):
        """Test honeypot service initializes correctly."""
        from decoyable.core.honeypot_service import HoneypotService

        # Register dependencies
        registry.register_instance("config", config)
        registry.register_instance("streaming_service", Mock())
        registry.register_instance("database_service", Mock())
        registry.register_instance("cache_service", Mock())

        service = HoneypotService(registry)

        assert not service._initialized
        assert service.attack_count == 0
        assert len(service.decoy_endpoints) == 0
        assert len(service.blocked_ips) == 0

    @pytest.mark.asyncio
    async def test_honeypot_service_async_init(self, registry, config):
        """Test async initialization of honeypot service."""
        from decoyable.core.honeypot_service import HoneypotService

        # Register dependencies
        registry.register_instance("config", config)
        registry.register_instance("streaming_service", Mock())
        registry.register_instance("database_service", Mock())
        registry.register_instance("cache_service", Mock())

        service = HoneypotService(registry)
        await service.initialize()

        assert service._initialized
        assert service.config is config

    @pytest.mark.asyncio
    async def test_process_attack(self, registry, config):
        """Test attack processing."""
        from decoyable.core.honeypot_service import HoneypotService

        # Register dependencies
        streaming_mock = AsyncMock()
        database_mock = AsyncMock()
        registry.register_instance("config", config)
        registry.register_instance("streaming_service", streaming_mock)
        registry.register_instance("database_service", database_mock)
        registry.register_instance("cache_service", Mock())

        service = HoneypotService(registry)
        await service.initialize()

        attack_data = {"ip_address": "192.168.1.100", "method": "GET", "path": "/admin", "user_agent": "Test Agent"}

        result = await service.process_attack(attack_data)

        assert result["processed"] is True
        assert service.attack_count == 1
        assert result["attack_id"] is not None  # Knowledge base is available

        # Verify streaming was called
        streaming_mock.publish_attack_event.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_decoy_endpoint(self, registry, config):
        """Test adding decoy endpoints."""
        from decoyable.core.honeypot_service import HoneypotService

        # Register dependencies
        registry.register_instance("config", config)
        registry.register_instance("streaming_service", Mock())
        registry.register_instance("database_service", Mock())
        registry.register_instance("cache_service", Mock())

        service = HoneypotService(registry)
        await service.initialize()

        await service.add_decoy_endpoint("/test-admin")

        assert "/test-admin" in service.decoy_endpoints

    @pytest.mark.asyncio
    async def test_block_ip(self, registry, config):
        """Test IP blocking functionality."""
        from decoyable.core.honeypot_service import HoneypotService

        # Register dependencies
        registry.register_instance("config", config)
        registry.register_instance("streaming_service", Mock())
        registry.register_instance("database_service", Mock())
        registry.register_instance("cache_service", Mock())

        service = HoneypotService(registry)
        await service.initialize()

        # Mock iptables to avoid system calls
        with patch("asyncio.create_subprocess_exec") as mock_subprocess:
            mock_proc = AsyncMock()
            mock_proc.wait.return_value = 0  # Success
            mock_subprocess.return_value = mock_proc

            success = await service.block_ip("192.168.1.100")

            # On systems without iptables, this will fail gracefully
            # The important thing is that it doesn't crash
            assert success is True or "192.168.1.100" in service.blocked_ips
            assert "192.168.1.100" in service.blocked_ips

    @pytest.mark.asyncio
    async def test_honeypot_status(self, registry, config):
        """Test honeypot status reporting."""
        from decoyable.core.honeypot_service import HoneypotService

        # Register dependencies
        registry.register_instance("config", config)
        registry.register_instance("streaming_service", Mock())
        registry.register_instance("database_service", Mock())
        registry.register_instance("cache_service", Mock())

        service = HoneypotService(registry)
        await service.initialize()

        status = await service.get_honeypot_status()

        assert "service_available" in status
        assert "initialized" in status
        assert "attack_count" in status
        assert status["initialized"] is True
        assert status["attack_count"] == 0

    @pytest.mark.asyncio
    async def test_health_check(self, registry, config):
        """Test honeypot service health checks."""
        from decoyable.core.honeypot_service import HoneypotService

        # Register dependencies
        registry.register_instance("config", config)
        registry.register_instance("streaming_service", Mock())
        registry.register_instance("database_service", Mock())
        registry.register_instance("cache_service", Mock())

        service = HoneypotService(registry)
        await service.initialize()

        health = await service.health_check()

        assert "honeypot_service" in health
        assert "defense_components" in health
        assert health["honeypot_service"] == "healthy"


class TestCLIServiceIntegration:
    """Test CLI service integration with all services."""

    @patch("decoyable.core.main.setup_services")
    def test_cli_service_commands(self, setup_services_mock):
        """Test that CLI service can handle all command types."""
        from decoyable.core.cli_service import CLIService
        from decoyable.core.registry import ServiceRegistry

        # Mock setup
        config_mock = Mock()
        registry_mock = ServiceRegistry()
        logging_mock = Mock()

        # Register mock services
        registry_mock.register_instance("streaming_service", Mock())
        registry_mock.register_instance("honeypot_service", Mock())
        registry_mock.register_instance("task_queue_service", Mock())
        registry_mock.register_instance("scanner_service", Mock())
        registry_mock.register_instance("database_service", Mock())

        setup_services_mock.return_value = (config_mock, registry_mock, None)

        cli_service = CLIService(config_mock, registry_mock, logging_mock)

        # Test that service methods exist
        assert hasattr(cli_service, "run_streaming_command")
        assert hasattr(cli_service, "run_honeypot_command")
        assert hasattr(cli_service, "run_task_command")
        assert hasattr(cli_service, "run_scan_command")

    def test_command_dispatching(self):
        """Test that commands are properly dispatched."""
        import sys

        from decoyable.core.main import main

        # Mock sys.argv to test command parsing
        original_argv = sys.argv
        try:
            # Test streaming command parsing
            sys.argv = ["decoyable", "streaming", "status"]
            # This would normally call the CLI, but we'll just test argument parsing
            from decoyable.core.main import build_arg_parser

            parser = build_arg_parser()
            args = parser.parse_args(["streaming", "status"])

            assert args.command == "streaming"
            assert args.streaming_command == "status"

            # Test honeypot command parsing
            args = parser.parse_args(["honeypot", "status"])
            assert args.command == "honeypot"
            assert args.honeypot_command == "status"

        finally:
            sys.argv = original_argv


class TestPerformanceValidation:
    """Test enterprise-grade performance validation."""

    @pytest.fixture
    def registry(self):
        """Create a test registry."""
        return ServiceRegistry()

    @pytest.mark.asyncio
    async def test_service_initialization_performance(self, registry):
        """Test that services initialize within performance requirements."""
        import time

        from decoyable.core.honeypot_service import HoneypotService
        from decoyable.core.streaming_service import StreamingService

        config = Settings()
        registry.register_instance("config", config)
        registry.register_instance("streaming_service", Mock())
        registry.register_instance("database_service", Mock())
        registry.register_instance("cache_service", Mock())

        # Test streaming service init performance
        start_time = time.time()
        streaming_service = StreamingService(registry)
        await streaming_service.initialize()
        init_time = time.time() - start_time

        # Should initialize in under 100ms
        assert init_time < 0.1, f"Streaming service init took {init_time:.3f}s"

        # Test honeypot service init performance
        start_time = time.time()
        honeypot_service = HoneypotService(registry)
        await honeypot_service.initialize()
        init_time = time.time() - start_time

        # Should initialize in under 100ms
        assert init_time < 0.1, f"Honeypot service init took {init_time:.3f}s"

    @pytest.mark.asyncio
    async def test_attack_processing_performance(self, registry):
        """Test attack processing performance meets latency requirements."""
        import time

        from decoyable.core.honeypot_service import HoneypotService

        config = Settings()
        registry.register_instance("config", config)
        registry.register_instance("streaming_service", AsyncMock())
        registry.register_instance("database_service", AsyncMock())
        registry.register_instance("cache_service", Mock())

        service = HoneypotService(registry)
        await service.initialize()

        attack_data = {"ip_address": "192.168.1.100", "method": "GET", "path": "/admin", "user_agent": "Test Agent"}

        # Test processing performance
        start_time = time.time()
        result = await service.process_attack(attack_data)
        process_time = time.time() - start_time

        # Should process attack in under 100ms (relaxed for test environment)
        assert process_time < 0.1, f"Attack processing took {process_time:.3f}s"
        assert result["processed"] is True


class TestErrorHandling:
    """Test comprehensive error handling."""

    @pytest.fixture
    def registry(self):
        """Create a test registry."""
        return ServiceRegistry()

    @pytest.mark.asyncio
    async def test_service_degradation_on_dependency_failure(self, registry):
        """Test services degrade gracefully when dependencies fail."""
        from decoyable.core.streaming_service import StreamingService

        config = Settings()
        registry.register_instance("config", config)

        # Don't register required dependencies
        service = StreamingService(registry)

        # Should initialize without crashing
        await service.initialize()
        assert service._initialized

        # Operations should fail gracefully
        success = await service.publish_attack_event("test", {})
        assert success is False

    @pytest.mark.asyncio
    async def test_partial_service_failure_handling(self, registry):
        """Test handling of partial service failures."""
        from decoyable.core.honeypot_service import HoneypotService

        config = Settings()
        registry.register_instance("config", config)

        # Register some dependencies but not others
        registry.register_instance("streaming_service", Mock())
        # Missing database_service and cache_service

        service = HoneypotService(registry)
        await service.initialize()

        # Should still initialize
        assert service._initialized

        # Should handle missing services gracefully
        attack_data = {"ip_address": "192.168.1.100", "method": "GET", "path": "/admin"}
        result = await service.process_attack(attack_data)

        assert result["processed"] is True
        # Should not crash even with missing dependencies
