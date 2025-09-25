"""
tests/test_streaming.py

Unit and integration tests for Kafka streaming components.
Tests producer/consumer flow, back-pressure handling, and error scenarios.
"""

import asyncio
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from decoyable.streaming.kafka_consumer import AttackEventConsumer
from decoyable.streaming.kafka_producer import KafkaAttackProducer


class TestKafkaAttackProducer:
    """Test Kafka producer functionality."""

    @pytest.fixture
    def mock_settings(self):
        """Mock settings for testing."""
        return MagicMock(
            kafka_enabled=True, kafka_bootstrap_servers=["localhost:9092"], kafka_attack_topic="test.attacks"
        )

    @patch("decoyable.streaming.kafka_producer.settings")
    def test_producer_disabled_when_kafka_not_enabled(self, mock_settings):
        """Test producer is disabled when Kafka is not enabled."""
        mock_settings.kafka_enabled = False

        producer = KafkaAttackProducer()
        assert not producer.enabled
        assert producer.producer is None

    @patch("decoyable.streaming.kafka_producer.AIOKafkaProducer")
    @patch("decoyable.streaming.kafka_producer.settings")
    def test_producer_initialization_success(self, mock_settings, mock_producer_class):
        """Test successful producer initialization."""
        mock_settings.kafka_enabled = True
        # Mock KAFKA_AVAILABLE
        with patch("decoyable.streaming.kafka_producer.KAFKA_AVAILABLE", True):
            mock_producer_instance = MagicMock()
            mock_producer_class.return_value = mock_producer_instance

            producer = KafkaAttackProducer()

            assert producer.enabled
            assert producer.producer == mock_producer_instance
            mock_producer_class.assert_called_once()

    @patch("decoyable.streaming.kafka_producer.settings")
    def test_producer_initialization_failure_missing_dependency(self, mock_settings):
        """Test producer initialization fails gracefully when aiokafka is not available."""
        with patch.dict("sys.modules", {"aiokafka": None}):
            producer = KafkaAttackProducer()

            assert not producer.enabled
            assert producer.producer is None

    @pytest.mark.asyncio
    @patch("decoyable.streaming.kafka_producer.settings")
    @patch("decoyable.streaming.kafka_producer.AIOKafkaProducer")
    async def test_publish_attack_event_success(self, mock_producer_class, mock_settings):
        """Test successful publishing of attack events."""
        mock_settings.kafka_enabled = True
        mock_settings.kafka_attack_topic = "test.attacks"
        with patch("decoyable.streaming.kafka_producer.KAFKA_AVAILABLE", True):
            mock_producer_instance = AsyncMock()
            mock_producer_class.return_value = mock_producer_instance

            producer = KafkaAttackProducer()
            await producer.start()

            attack_data = {
                "ip_address": "192.168.1.100",
                "method": "GET",
                "path": "/admin",
                "timestamp": "2024-01-01T00:00:00Z",
            }

            result = await producer.publish_attack_event(attack_data)

            assert result is True
            mock_producer_instance.send_and_wait.assert_called_once()

            # Check the event structure
            call_args = mock_producer_instance.send_and_wait.call_args
            topic = call_args[0][0]
            event = call_args[1]["value"]

            assert topic == "test.attacks"
            assert event == attack_data

    @pytest.mark.asyncio
    @patch("decoyable.streaming.kafka_producer.settings")
    async def test_publish_attack_event_disabled(self, mock_settings):
        """Test publishing fails gracefully when producer is disabled."""
        mock_settings.kafka_enabled = False

        producer = KafkaAttackProducer()

        result = await producer.publish_attack_event({"test": "data"})

        assert result is False

    @pytest.mark.asyncio
    @patch("decoyable.streaming.kafka_producer.settings")
    @patch("decoyable.streaming.kafka_producer.AIOKafkaProducer")
    async def test_publish_attack_event_failure(self, mock_producer_class, mock_settings):
        """Test publishing handles Kafka errors gracefully."""
        mock_producer_instance = AsyncMock()
        mock_producer_instance.send_and_wait.side_effect = Exception("Kafka error")
        mock_producer_class.return_value = mock_producer_instance

        producer = KafkaAttackProducer()
        await producer.start()

        result = await producer.publish_attack_event({"test": "data"})

        assert result is False


class TestAttackEventConsumer:
    """Test Kafka consumer functionality."""

    @pytest.fixture
    def mock_settings(self):
        """Mock settings for testing."""
        return MagicMock(
            kafka_enabled=True, kafka_bootstrap_servers=["localhost:9092"], kafka_attack_topic="test.attacks"
        )

    @patch("decoyable.streaming.kafka_consumer.settings")
    def test_consumer_disabled_when_kafka_not_enabled(self, mock_settings):
        """Test consumer is disabled when Kafka is not enabled."""
        mock_settings.kafka_enabled = False

        consumer = AttackEventConsumer("test")
        assert not consumer.enabled
        assert consumer.consumer is None

    @patch("decoyable.streaming.kafka_consumer.settings")
    @patch("decoyable.streaming.kafka_consumer.AIOKafkaConsumer")
    def test_consumer_initialization_success(self, mock_consumer_class, mock_settings):
        """Test successful consumer initialization."""
        mock_consumer_instance = MagicMock()
        mock_consumer_class.return_value = mock_consumer_instance

        consumer = AttackEventConsumer("test")

        assert consumer.enabled
        assert consumer.consumer == mock_consumer_instance
        assert consumer.group_id == "decoyable-test"
        mock_consumer_class.assert_called_once()

    @pytest.mark.asyncio
    @patch("decoyable.streaming.kafka_consumer.analyze_attack_async")
    @patch("decoyable.streaming.kafka_consumer.apply_adaptive_defense")
    async def test_process_analysis_event(self, mock_adaptive_defense, mock_analyze):
        """Test processing analysis events."""
        mock_analyze.return_value = {"attack_type": "brute_force", "confidence": 0.9}

        consumer = AttackEventConsumer("analysis")

        event = {"event_type": "attack_detected", "data": {"ip_address": "192.168.1.100", "method": "POST"}}

        await consumer._process_analysis_event(event["event_type"], event["data"])

        mock_analyze.assert_called_once_with(event["data"])
        mock_adaptive_defense.assert_called_once()

    @pytest.mark.asyncio
    @patch("decoyable.streaming.kafka_consumer.forward_alert")
    async def test_process_alert_event(self, mock_forward_alert):
        """Test processing alert events."""
        consumer = AttackEventConsumer("alerts")

        event = {"event_type": "attack_detected", "data": {"ip_address": "192.168.1.100", "alert_type": "suspicious"}}

        await consumer._process_alert_event(event["event_type"], event["data"])

        mock_forward_alert.assert_called_once()

    @pytest.mark.asyncio
    @patch("decoyable.streaming.kafka_consumer.knowledge_base")
    async def test_process_persistence_event(self, mock_kb):
        """Test processing persistence events."""
        mock_kb.store_attack.return_value = 123

        consumer = AttackEventConsumer("persistence")

        event = {"event_type": "attack_detected", "data": {"ip_address": "192.168.1.100"}}

        await consumer._process_persistence_event(event["event_type"], event["data"])

        mock_kb.store_attack.assert_called_once_with(event["data"])


class TestStreamingIntegration:
    """Integration tests for streaming components."""

    @pytest.mark.asyncio
    @patch("decoyable.streaming.kafka_producer.settings")
    @patch("decoyable.streaming.kafka_consumer.settings")
    async def test_end_to_end_flow(self, mock_consumer_settings, mock_producer_settings):
        """Test end-to-end producer to consumer flow."""
        # Setup mock settings
        for mock_settings in [mock_producer_settings, mock_consumer_settings]:
            mock_settings.kafka_enabled = True
            mock_settings.kafka_bootstrap_servers = ["localhost:9092"]
            mock_settings.kafka_attack_topic = "test.attacks"

        # Create producer
        producer = KafkaAttackProducer()

        # Mock the producer's internal producer
        mock_kafka_producer = AsyncMock()
        producer.producer = mock_kafka_producer

        # Create consumer
        consumer = AttackEventConsumer("analysis")

        # Mock the consumer's internal consumer
        mock_kafka_consumer = MagicMock()
        consumer.consumer = mock_kafka_consumer

        # Mock message iteration
        mock_message = MagicMock()
        mock_message.value = {"event_type": "attack_detected", "data": {"ip_address": "192.168.1.100", "method": "GET"}}
        mock_kafka_consumer.__aiter__.return_value = [mock_message]

        # Test producer publishing
        attack_data = {"ip_address": "192.168.1.100", "method": "GET"}
        result = await producer.publish_attack_event(attack_data)
        assert result is True

        # Verify the message was sent
        mock_kafka_producer.send_and_wait.assert_called_once()

    @pytest.mark.asyncio
    async def test_back_pressure_simulation(self):
        """Test back-pressure handling under load."""
        # This would test rate limiting and queue management
        # For now, just ensure the components can handle concurrent operations

        producer = KafkaAttackProducer()
        producer.enabled = False  # Disable to avoid actual Kafka calls

        # Simulate concurrent publishing
        tasks = []
        for i in range(10):
            task = producer.publish_attack_event({"ip_address": f"192.168.1.{i}", "method": "GET", "request_id": i})
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # All should return False since producer is disabled
        assert all(result is False for result in results)


class TestConfiguration:
    """Test configuration handling."""

    def test_kafka_settings_parsing(self):
        """Test that Kafka settings are parsed correctly."""
        from decoyable.core.config import Settings

        # Test with environment variables
        env_vars = {
            "KAFKA_ENABLED": "true",
            "KAFKA_BOOTSTRAP_SERVERS": "kafka1:9092,kafka2:9092",
            "KAFKA_ATTACK_TOPIC": "custom.attacks",
        }

        with patch.dict("os.environ", env_vars, clear=True):
            settings = Settings()

            assert settings.kafka_enabled is True
            assert settings.kafka_bootstrap_servers == "kafka1:9092,kafka2:9092"
            assert settings.kafka_attack_topic == "custom.attacks"

    def test_kafka_settings_defaults(self):
        """Test default Kafka settings."""
        from decoyable.core.config import Settings

        # Clear any existing env vars
        env_vars = {k: v for k, v in os.environ.items() if not k.startswith("KAFKA_")}

        with patch.dict("os.environ", env_vars, clear=True):
            settings = Settings()

            assert settings.kafka_enabled is False
            assert settings.kafka_bootstrap_servers == "localhost:9092"
            assert settings.kafka_attack_topic == "decoyable.attacks"
