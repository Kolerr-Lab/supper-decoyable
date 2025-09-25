"""
Streaming Service Module

Provides Kafka-based event streaming with service registry integration.
Handles attack event publishing and consumption with dependency injection.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional

from decoyable.core.registry import ServiceRegistry

logger = logging.getLogger(__name__)

# Optional Kafka imports
try:
    from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

    KAFKA_AVAILABLE = True
except ImportError:
    AIOKafkaProducer = None
    AIOKafkaConsumer = None
    KAFKA_AVAILABLE = False

# Import existing streaming components
try:
    from decoyable.streaming.kafka_consumer import AttackEventConsumer
    from decoyable.streaming.kafka_producer import KafkaAttackProducer

    STREAMING_AVAILABLE = True
except ImportError:
    KafkaAttackProducer = None
    AttackEventConsumer = None
    STREAMING_AVAILABLE = False


class StreamingService:
    """
    Kafka-based streaming service with dependency injection.

    Provides high-throughput event streaming for attack events, analysis results,
    and security alerts. Integrates with the service registry for clean architecture.
    """

    def __init__(self, registry: ServiceRegistry):
        """
        Initialize streaming service with service registry.

        Args:
            registry: Service registry for dependency injection
        """
        self.registry = registry
        self.producer = None
        self.consumers = {}
        self.config = None
        self.database_service = None
        self.cache_service = None
        self._initialized = False
        self._running = False

    async def initialize(self) -> None:
        """Initialize the streaming service asynchronously."""
        if self._initialized:
            return

        if not STREAMING_AVAILABLE:
            logger.warning("Streaming components not available. Streaming functionality disabled.")
            self._initialized = True
            return

        try:
            # Get service dependencies
            self.config = self.registry.get_by_name("config")
            self.database_service = self.registry.get_by_name("database_service")
            self.cache_service = self.registry.get_by_name("cache_service")

            # Initialize producer if Kafka is available
            if KAFKA_AVAILABLE and self.config.kafka_enabled:
                self.producer = KafkaAttackProducer()
                await self.producer.start()
                logger.info("Streaming producer initialized")
            else:
                logger.info("Kafka producer disabled (not configured or not available)")

            # Initialize consumers
            consumer_types = ["analysis", "alerts", "persistence"]
            for consumer_type in consumer_types:
                if KAFKA_AVAILABLE and self.config.kafka_enabled:
                    consumer = AttackEventConsumer(consumer_type)
                    self.consumers[consumer_type] = consumer
                    logger.info(f"Streaming consumer initialized: {consumer_type}")
                else:
                    logger.info(f"Kafka consumer disabled for {consumer_type}")

            self._initialized = True
            logger.info("Streaming service initialized successfully")

        except Exception as e:
            logger.warning(f"Failed to initialize streaming service: {e}. Streaming disabled.")
            self._initialized = True

    async def start_consumers(self) -> None:
        """Start all configured consumers."""
        if not self._initialized or self._running:
            return

        if not self.consumers:
            logger.info("No consumers configured")
            return

        self._running = True
        logger.info("Starting streaming consumers...")

        # Start consumers in background tasks
        consumer_tasks = []
        for consumer_type, consumer in self.consumers.items():
            if consumer.enabled:
                task = asyncio.create_task(self._run_consumer(consumer_type, consumer))
                consumer_tasks.append(task)
                logger.info(f"Started consumer: {consumer_type}")

        if consumer_tasks:
            # Wait for any consumer to finish (they run indefinitely)
            await asyncio.gather(*consumer_tasks, return_exceptions=True)

        self._running = False

    async def stop_consumers(self) -> None:
        """Stop all running consumers."""
        if not self._running:
            return

        logger.info("Stopping streaming consumers...")
        self._running = False

        # Stop all consumers
        stop_tasks = []
        for consumer in self.consumers.values():
            if consumer.enabled:
                stop_tasks.append(consumer.stop())

        if stop_tasks:
            await asyncio.gather(*stop_tasks, return_exceptions=True)

        logger.info("Streaming consumers stopped")

    async def _run_consumer(self, consumer_type: str, consumer) -> None:
        """Run a consumer in a loop."""
        try:
            await consumer.start()
            await consumer.consume_events()
        except Exception as e:
            logger.error(f"Consumer {consumer_type} failed: {e}")
        finally:
            await consumer.stop()

    async def publish_attack_event(
        self,
        event_type: str,
        data: Dict[str, Any],
        key: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Publish an attack event to the streaming platform.

        Args:
            event_type: Type of event (e.g., 'attack_detected', 'security_alert')
            data: Event data payload
            key: Optional partitioning key
            metadata: Optional additional metadata

        Returns:
            True if published successfully
        """
        await self.initialize()

        if not self.producer or not self.producer.enabled:
            logger.debug("Streaming producer not available")
            return False

        try:
            # Construct full event
            event = {
                "event_type": event_type,
                "data": data,
                "timestamp": asyncio.get_event_loop().time(),
            }

            if metadata:
                event["metadata"] = metadata

            # Publish to streaming platform
            success = await self.producer.publish_attack_event(event, key)

            if success:
                # Also store in database if available
                if self.database_service:
                    try:
                        await self.database_service.store_attack_event(event)
                    except Exception as e:
                        logger.warning(f"Failed to store event in database: {e}")

                # Cache recent events if cache service available
                if self.cache_service:
                    try:
                        cache_key = f"recent_event:{event_type}:{key or 'nokey'}"
                        await self.cache_service.set(cache_key, event, ttl=300)  # 5 minutes
                    except Exception as e:
                        logger.warning(f"Failed to cache event: {e}")

            return success

        except Exception as e:
            logger.error(f"Failed to publish attack event: {e}")
            return False

    async def publish_security_alert(
        self,
        alert_type: str,
        severity: str,
        message: str,
        source_ip: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Publish a security alert.

        Args:
            alert_type: Type of security alert
            severity: Alert severity (low, medium, high, critical)
            message: Alert message
            source_ip: Source IP address if applicable
            details: Additional alert details

        Returns:
            True if published successfully
        """
        alert_data = {
            "alert_type": alert_type,
            "severity": severity,
            "message": message,
            "source_ip": source_ip,
            "details": details or {},
        }

        return await self.publish_attack_event(
            "security_alert",
            alert_data,
            key=source_ip,
            metadata={"alert_id": f"{alert_type}_{asyncio.get_event_loop().time()}"},
        )

    async def publish_scan_result(
        self, scan_type: str, target_path: str, results: Dict[str, Any], scan_duration_ms: float
    ) -> bool:
        """
        Publish scan results to streaming platform.

        Args:
            scan_type: Type of scan performed
            target_path: Path that was scanned
            results: Scan results data
            scan_duration_ms: Scan duration in milliseconds

        Returns:
            True if published successfully
        """
        scan_data = {
            "scan_type": scan_type,
            "target_path": target_path,
            "results": results,
            "scan_duration_ms": scan_duration_ms,
            "scan_timestamp": asyncio.get_event_loop().time(),
        }

        return await self.publish_attack_event("scan_completed", scan_data, key=target_path)

    async def get_streaming_stats(self) -> Dict[str, Any]:
        """
        Get streaming service statistics and health information.

        Returns:
            Streaming statistics
        """
        await self.initialize()

        stats = {
            "service_available": STREAMING_AVAILABLE,
            "kafka_available": KAFKA_AVAILABLE,
            "producer_enabled": self.producer is not None and getattr(self.producer, "enabled", False),
            "consumers_configured": len(self.consumers),
            "consumers_enabled": sum(1 for c in self.consumers.values() if getattr(c, "enabled", False)),
            "service_running": self._running,
        }

        if self.config:
            stats.update(
                {
                    "kafka_enabled": getattr(self.config, "kafka_enabled", False),
                    "bootstrap_servers": getattr(self.config, "kafka_bootstrap_servers", None),
                    "topic": getattr(self.config, "kafka_attack_topic", None),
                }
            )

        return stats

    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on streaming components.

        Returns:
            Health check results
        """
        await self.initialize()

        health = {
            "streaming_service": "healthy" if self._initialized else "unhealthy",
            "producer": "unknown",
            "consumers": {},
        }

        # Check producer health
        if self.producer and hasattr(self.producer, "producer"):
            try:
                # Simple health check - producer exists and is initialized
                health["producer"] = "healthy"
            except Exception:
                health["producer"] = "unhealthy"
        else:
            health["producer"] = "disabled"

        # Check consumer health
        for consumer_type, consumer in self.consumers.items():
            if consumer and getattr(consumer, "enabled", False):
                health["consumers"][consumer_type] = "healthy"
            else:
                health["consumers"][consumer_type] = "disabled"

        return health
