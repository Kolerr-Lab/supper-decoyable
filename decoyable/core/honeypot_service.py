"""
Honeypot Service Module

Refactored honeypot system with service registry integration and clean architecture.
Provides active defense capabilities with dependency injection and modular design.
"""

import asyncio
import json
import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from decoyable.core.registry import ServiceRegistry

logger = logging.getLogger(__name__)

# Optional imports for graceful degradation
try:
    import httpx

    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

try:
    from decoyable.defense.adaptive_defense import AdaptiveDefense
    from decoyable.defense.analysis import analyze_attack_async
    from decoyable.defense.knowledge_base import KnowledgeBase

    DEFENSE_AVAILABLE = True
except ImportError:
    DEFENSE_AVAILABLE = False
    analyze_attack_async = None
    AdaptiveDefense = None
    KnowledgeBase = None


class HoneypotService:
    """
    Honeypot service with dependency injection and service registry integration.

    Provides active defense capabilities including:
    - Decoy endpoint management
    - Attack capture and analysis
    - Adaptive defense rules
    - IP blocking and alerting
    - Knowledge base integration
    """

    def __init__(self, registry: ServiceRegistry):
        """
        Initialize honeypot service with service registry.

        Args:
            registry: Service registry for dependency injection
        """
        self.registry = registry
        self.config = None
        self.streaming_service = None
        self.database_service = None
        self.cache_service = None
        self.knowledge_base = None
        self.adaptive_defense = None
        self._initialized = False
        self._running = False

        # Honeypot state
        self.decoy_endpoints: Set[str] = set()
        self.blocked_ips: Set[str] = set()
        self.attack_count = 0
        self.last_attack_time = None

    async def initialize(self) -> None:
        """Initialize the honeypot service asynchronously."""
        if self._initialized:
            return

        try:
            # Get service dependencies
            self.config = self.registry.get_by_name("config")
            self.streaming_service = self.registry.get_by_name("streaming_service")
            self.database_service = self.registry.get_by_name("database_service")
            self.cache_service = self.registry.get_by_name("cache_service")

            # Initialize defense components if available
            if DEFENSE_AVAILABLE:
                # Initialize knowledge base
                kb_path = (
                    getattr(self.config, "knowledge_db_path", "decoyable_knowledge.db")
                    if self.config
                    else "decoyable_knowledge.db"
                )
                self.knowledge_base = KnowledgeBase(kb_path)

                # Initialize adaptive defense
                self.adaptive_defense = AdaptiveDefense()

                logger.info("Defense components initialized")
            else:
                logger.warning("Defense components not available. Honeypot functionality limited.")

            # Load initial decoy endpoints from config
            if self.config and hasattr(self.config, "honeypot"):
                initial_endpoints = getattr(self.config.honeypot, "decoy_endpoints", [])
                self.decoy_endpoints.update(initial_endpoints)

            self._initialized = True
            logger.info("Honeypot service initialized successfully")

        except Exception as e:
            logger.warning(f"Failed to initialize honeypot service: {e}. Honeypot disabled.")
            self._initialized = True

    async def process_attack(
        self, attack_data: Dict[str, Any], background_tasks: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Process a captured attack.

        Args:
            attack_data: Attack log data
            background_tasks: Optional FastAPI background tasks

        Returns:
            Processing result
        """
        await self.initialize()

        self.attack_count += 1
        self.last_attack_time = datetime.utcnow()

        ip_address = attack_data.get("ip_address", "unknown")
        method = attack_data.get("method", "UNKNOWN")
        path = attack_data.get("path", "/")

        logger.warning(f"Honeypot attack detected: {method} {path} from {ip_address}")

        result = {"processed": True, "attack_id": None, "actions_taken": [], "timestamp": datetime.utcnow().isoformat()}

        try:
            # Analyze attack if analysis is available
            analysis_result = {}
            if analyze_attack_async:
                analysis_result = await analyze_attack_async(attack_data)
                result["analysis"] = analysis_result

            # Store in knowledge base if available
            if self.knowledge_base:
                try:
                    attack_id = self.knowledge_base.store_analysis(attack_data, analysis_result)
                    result["attack_id"] = attack_id
                except Exception as e:
                    logger.error(f"Failed to store attack in knowledge base: {e}")

            # Store in database if available
            if self.database_service:
                try:
                    await self.database_service.store_attack_event(
                        {
                            "event_type": "honeypot_attack",
                            "data": attack_data,
                            "analysis": analysis_result,
                            "timestamp": result["timestamp"],
                        }
                    )
                except Exception as e:
                    logger.error(f"Failed to store attack in database: {e}")

            # Publish to streaming service if available
            if self.streaming_service:
                try:
                    success = await self.streaming_service.publish_attack_event(
                        "honeypot_attack", {**attack_data, "analysis": analysis_result}, key=ip_address
                    )
                    if success:
                        result["actions_taken"].append("streamed")
                except Exception as e:
                    logger.error(f"Failed to stream attack event: {e}")

            # Apply adaptive defense
            await self._apply_adaptive_defense(attack_data, analysis_result, result)

            # Forward alerts
            await self._forward_alerts(attack_data, analysis_result, result)

        except Exception as e:
            logger.error(f"Error processing honeypot attack: {e}")
            result["error"] = str(e)

        return result

    async def _apply_adaptive_defense(
        self, attack_data: Dict[str, Any], analysis_result: Dict[str, Any], result: Dict[str, Any]
    ) -> None:
        """Apply adaptive defense measures."""
        if not self.adaptive_defense:
            return

        ip_address = attack_data.get("ip_address", "unknown")
        recommended_action = analysis_result.get("recommended_action")

        # Apply recommended action
        if recommended_action in ("block", "block_ip"):
            await self.block_ip(ip_address)
            result["actions_taken"].append("ip_blocked")

        # Update adaptive patterns
        attack_type = analysis_result.get("attack_type")
        if attack_type:
            # Add new patterns based on this attack
            path = attack_data.get("path", "")
            if path and len(path) > 5:  # Avoid adding very short paths
                self.adaptive_defense.add_pattern(attack_type, path)
                result["actions_taken"].append("pattern_added")

    async def _forward_alerts(
        self, attack_data: Dict[str, Any], analysis_result: Dict[str, Any], result: Dict[str, Any]
    ) -> None:
        """Forward alerts to configured endpoints."""
        if not self.config or not hasattr(self.config, "honeypot"):
            return

        security_endpoint = getattr(self.config.honeypot, "security_team_endpoint", None)
        if not security_endpoint or not HTTPX_AVAILABLE:
            return

        alert_data = {
            "attack": attack_data,
            "analysis": analysis_result,
            "timestamp": datetime.utcnow().isoformat(),
            "honeypot_service": "decoyable",
        }

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(
                    security_endpoint, json=alert_data, headers={"Content-Type": "application/json"}
                )
                if resp.status_code >= 200 and resp.status_code < 300:
                    logger.info("Alert forwarded to security endpoint")
                    result["actions_taken"].append("alert_forwarded")
                else:
                    logger.error(f"Security endpoint returned {resp.status_code}: {resp.text}")
        except Exception as e:
            logger.error(f"Failed to forward alert: {e}")

    async def block_ip(self, ip: str) -> bool:
        """
        Block an IP address.

        Args:
            ip: IP address to block

        Returns:
            True if blocked successfully
        """
        if ip in self.blocked_ips:
            return True

        self.blocked_ips.add(ip)

        # Update adaptive defense
        if self.adaptive_defense:
            self.adaptive_defense.block_ip(ip)

        # Apply system-level blocking
        try:
            # Use iptables on Linux systems
            proc = await asyncio.create_subprocess_exec(
                "iptables",
                "-A",
                "INPUT",
                "-s",
                ip,
                "-j",
                "DROP",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.wait(), timeout=8.0)

            if proc.returncode == 0:
                logger.info(f"Blocked IP {ip} via iptables")
                return True
            else:
                stderr = await proc.stderr.read()
                logger.error(f"iptables failed for {ip}: {stderr}")
                return False

        except FileNotFoundError:
            logger.warning("iptables not found; IP blocking not available on this system")
            return False
        except asyncio.TimeoutError:
            logger.error(f"Timeout while blocking IP {ip}")
            return False
        except Exception as e:
            logger.error(f"Error blocking IP {ip}: {e}")
            return False

    async def add_decoy_endpoint(self, endpoint: str) -> None:
        """
        Add a new decoy endpoint.

        Args:
            endpoint: Endpoint path to add
        """
        self.decoy_endpoints.add(endpoint)

        if self.adaptive_defense:
            self.adaptive_defense.add_decoy_endpoint(endpoint)

        logger.info(f"Added decoy endpoint: {endpoint}")

    async def get_honeypot_status(self) -> Dict[str, Any]:
        """
        Get honeypot service status and statistics.

        Returns:
            Status information
        """
        await self.initialize()

        return {
            "service_available": DEFENSE_AVAILABLE,
            "initialized": self._initialized,
            "running": self._running,
            "attack_count": self.attack_count,
            "last_attack_time": self.last_attack_time.isoformat() if self.last_attack_time else None,
            "blocked_ips_count": len(self.blocked_ips),
            "decoy_endpoints_count": len(self.decoy_endpoints),
            "knowledge_base_available": self.knowledge_base is not None,
            "adaptive_defense_available": self.adaptive_defense is not None,
            "streaming_available": self.streaming_service is not None,
            "database_available": self.database_service is not None,
            "cache_available": self.cache_service is not None,
        }

    async def get_recent_attacks(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recent attacks from knowledge base.

        Args:
            limit: Maximum number of attacks to return

        Returns:
            List of recent attacks
        """
        if not self.knowledge_base:
            return []

        try:
            return self.knowledge_base.get_recent_attacks(limit)
        except Exception as e:
            logger.error(f"Failed to get recent attacks: {e}")
            return []

    async def get_attack_patterns(self) -> Dict[str, List[str]]:
        """
        Get all attack patterns (static + dynamic).

        Returns:
            Dictionary of attack patterns
        """
        if not self.adaptive_defense:
            return {}

        return self.adaptive_defense.get_all_patterns()

    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on honeypot components.

        Returns:
            Health check results
        """
        await self.initialize()

        health = {
            "honeypot_service": "healthy" if self._initialized else "unhealthy",
            "defense_components": "healthy" if DEFENSE_AVAILABLE else "unavailable",
            "knowledge_base": "unknown",
            "adaptive_defense": "unknown",
            "streaming_integration": "unknown",
            "database_integration": "unknown",
        }

        # Check knowledge base
        if self.knowledge_base:
            try:
                # Simple health check - try to get recent attacks
                recent = self.knowledge_base.get_recent_attacks(1)
                health["knowledge_base"] = "healthy"
            except Exception:
                health["knowledge_base"] = "unhealthy"
        else:
            health["knowledge_base"] = "disabled"

        # Check adaptive defense
        if self.adaptive_defense:
            health["adaptive_defense"] = "healthy"
        else:
            health["adaptive_defense"] = "disabled"

        # Check integrations
        health["streaming_integration"] = "healthy" if self.streaming_service else "disabled"
        health["database_integration"] = "healthy" if self.database_service else "disabled"

        return health
