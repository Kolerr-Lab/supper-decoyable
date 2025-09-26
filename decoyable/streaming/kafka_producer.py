"""
Kafka producer for DECOYABLE attack events.
Provides optional high-throughput streaming capabilities.
"""

import json
import logging
from typing import Any, Dict, Optional

from decoyable.core.config import settings

logger = logging.getLogger(__name__)

# Import Kafka classes for patching in tests
try:
    from aiokafka import AIOKafkaProducer

    KAFKA_AVAILABLE = True
except ImportError:
    AIOKafkaProducer = None  # For patching in tests
    KAFKA_AVAILABLE = False
    logger.warning("aiokafka not available. Kafka streaming disabled.")


class KafkaAttackProducer:
    """
    Optional Kafka producer for publishing attack events.
    Gracefully degrades when Kafka is not available.
    """

    def __init__(
        self,
        bootstrap_servers: Optional[str] = None,
        topic: Optional[str] = None,
        client_id: str = "decoyable-producer",
    ):
        self.bootstrap_servers = bootstrap_servers or settings.kafka_bootstrap_servers
        self.topic = topic or settings.kafka_attack_topic
        self.client_id = client_id
        self.enabled = settings.kafka_enabled and KAFKA_AVAILABLE
        self.producer: Optional[Any] = None

        if self.enabled:
            self._init_producer()

    def _init_producer(self):
        """Initialize the Kafka producer."""
        try:
            self.producer = AIOKafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                client_id=self.client_id,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                key_serializer=lambda k: str(k).encode("utf-8") if k else None,
                acks="all",  # Wait for all replicas
            )
        except Exception as e:
            logger.error(f"Failed to create Kafka producer: {e}")
            self.producer = None

    async def start(self) -> None:
        """Start the Kafka producer."""
        if self.producer:
            try:
                await self.producer.start()
                logger.info(f"Kafka producer started for topic: {self.topic}")
            except Exception as e:
                logger.error(f"Failed to start Kafka producer: {e}")
                self.producer = None

    async def stop(self) -> None:
        """Stop the Kafka producer."""
        if self.producer:
            try:
                await self.producer.stop()
                logger.info("Kafka producer stopped")
            except Exception as e:
                logger.error(f"Error stopping Kafka producer: {e}")

    async def publish_attack_event(self, event: Dict[str, Any], key: Optional[str] = None) -> bool:
        """
        Publish an attack event to Kafka.

        Args:
            event: Attack event data
            key: Optional partitioning key

        Returns:
            True if published successfully, False otherwise
        """
        if not self.producer:
            logger.debug("Kafka producer not available, skipping event publication")
            return False

        try:
            # Add timestamp if not present
            if "timestamp" not in event:
                import time

                event["timestamp"] = time.time()

            await self.producer.send_and_wait(self.topic, value=event, key=key)

            logger.debug(f"Published attack event: {event.get('type', 'unknown')}")
            return True

        except Exception as e:
            logger.error(f"Failed to publish attack event: {e}")
            return False

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop()
