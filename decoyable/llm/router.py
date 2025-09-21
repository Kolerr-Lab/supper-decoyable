"""
decoyable/llm/router.py

Smart LLM routing engine with failover, load balancing, and error handling.
Routes requests to available providers based on health, priority, and performance.
"""

import asyncio
import logging
import random
import time
from typing import Any, Dict, List, Optional, Tuple

from .base import LLMProvider, ProviderConfig, ProviderStatus
from . import factory as provider_factory
create_provider = provider_factory.create_provider

logger = logging.getLogger(__name__)


class RoutingStrategy:
    """Base class for routing strategies."""

    def select_provider(self, providers: List[LLMProvider]) -> Optional[LLMProvider]:
        """Select a provider from the available list."""
        raise NotImplementedError


class PriorityRouting(RoutingStrategy):
    """Route to highest priority healthy provider."""

    def select_provider(self, providers: List[LLMProvider]) -> Optional[LLMProvider]:
        """Select provider by priority (lowest number first)."""
        healthy_providers = [p for p in providers if p.is_healthy() and p.should_attempt_request()]
        if not healthy_providers:
            return None

        # Sort by priority (ascending) then by performance metrics
        healthy_providers.sort(key=lambda p: (p.config.priority, p.metrics.total_latency / max(p.metrics.total_requests, 1)))
        return healthy_providers[0]


class LoadBalancingRouting(RoutingStrategy):
    """Load balance across healthy providers."""

    def select_provider(self, providers: List[LLMProvider]) -> Optional[LLMProvider]:
        """Select provider using weighted random selection based on performance."""
        healthy_providers = [p for p in providers if p.is_healthy() and p.should_attempt_request()]
        if not healthy_providers:
            return None

        # Weight by inverse of average latency (lower latency = higher weight)
        weights = []
        for provider in healthy_providers:
            avg_latency = provider.metrics.total_latency / max(provider.metrics.total_requests, 1)
            # Avoid division by zero and very high weights
            weight = max(0.1, 1.0 / max(avg_latency, 0.001))
            weights.append(weight)

        # Normalize weights
        total_weight = sum(weights)
        if total_weight == 0:
            return random.choice(healthy_providers)

        normalized_weights = [w / total_weight for w in weights]

        # Weighted random selection
        r = random.random()
        cumulative = 0
        for provider, weight in zip(healthy_providers, normalized_weights):
            cumulative += weight
            if r <= cumulative:
                return provider

        return healthy_providers[-1]  # Fallback


class FailoverRouting(RoutingStrategy):
    """Simple failover routing - try providers in priority order."""

    def select_provider(self, providers: List[LLMProvider]) -> Optional[LLMProvider]:
        """Select first healthy provider in priority order."""
        sorted_providers = sorted(providers, key=lambda p: p.config.priority)
        for provider in sorted_providers:
            if provider.is_healthy() and provider.should_attempt_request():
                return provider
        return None


class LLMRouter:
    """Smart LLM routing engine with failover and load balancing."""

    def __init__(self,
                 provider_configs: List[ProviderConfig],
                 routing_strategy: RoutingStrategy = None,
                 max_retries: int = 3,
                 retry_delay: float = 1.0,
                 health_check_interval: int = 60,
                 start_health_checks: bool = True):
        """
        Initialize the LLM router.

        Args:
            provider_configs: List of provider configurations
            routing_strategy: Strategy for selecting providers
            max_retries: Maximum number of retry attempts
            retry_delay: Delay between retries (exponential backoff)
            health_check_interval: How often to check provider health (seconds)
            start_health_checks: Whether to start background health checks
        """
        self.providers: Dict[str, LLMProvider] = {}
        self.routing_strategy = routing_strategy or PriorityRouting()
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.health_check_interval = health_check_interval
        self.last_health_check = 0

        # Initialize providers
        for config in provider_configs:
            try:
                provider = create_provider(config.name.lower(), config)
                self.providers[config.name] = provider
                logger.info(f"Initialized LLM provider: {config.name}")
            except Exception as e:
                logger.error(f"Failed to initialize provider {config.name}: {e}")

        # Start background health checking (can be disabled for testing)
        if start_health_checks:
            asyncio.create_task(self._health_check_loop())

    async def _health_check_loop(self):
        """Background task to periodically check provider health."""
        while True:
            try:
                await self._check_all_providers_health()
                self.last_health_check = time.time()
            except Exception as e:
                logger.error(f"Health check failed: {e}")

            await asyncio.sleep(self.health_check_interval)

    async def _check_all_providers_health(self):
        """Check health of all providers."""
        tasks = []
        for provider in self.providers.values():
            if provider.config.enabled:
                tasks.append(self._check_provider_health(provider))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_provider_health(self, provider: LLMProvider):
        """Check health of a single provider."""
        try:
            is_healthy = await provider.check_health()
            if is_healthy and provider.status != ProviderStatus.HEALTHY:
                logger.info(f"Provider {provider.name} is now healthy")
            elif not is_healthy and provider.status == ProviderStatus.HEALTHY:
                logger.warning(f"Provider {provider.name} is now unhealthy")
        except Exception as e:
            logger.error(f"Health check failed for {provider.name}: {e}")

    def get_provider_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all providers."""
        status = {}
        for name, provider in self.providers.items():
            status[name] = {
                "status": provider.status.value,
                "healthy": provider.is_healthy(),
                "metrics": {
                    "total_requests": provider.metrics.total_requests,
                    "successful_requests": provider.metrics.successful_requests,
                    "failed_requests": provider.metrics.failed_requests,
                    "average_latency": provider.metrics.total_latency / max(provider.metrics.total_requests, 1),
                    "consecutive_failures": provider.metrics.consecutive_failures,
                    "rate_limit_hits": provider.metrics.rate_limit_hits,
                },
                "config": {
                    "enabled": provider.config.enabled,
                    "priority": provider.config.priority,
                    "model": provider.config.model,
                }
            }
        return status

    async def _generate_with_specific_provider(self,
                                             prompt: str,
                                             provider_name: str,
                                             **kwargs) -> Tuple[Dict[str, Any], str]:
        """Generate completion using a specific provider."""
        provider = self.providers[provider_name]
        if not provider.is_healthy() or not provider.should_attempt_request():
            raise ValueError(f"Requested provider {provider_name} is not available")

        try:
            response = await provider.generate_completion(prompt, **kwargs)
            return response, provider_name
        except Exception as e:
            logger.error(f"Specific provider {provider_name} failed: {e}")
            raise

    async def _generate_with_routing(self,
                                   prompt: str,
                                   **kwargs) -> Tuple[Dict[str, Any], str]:
        """Generate completion using routing strategy with retries."""
        for attempt in range(self.max_retries):
            provider = self.routing_strategy.select_provider(list(self.providers.values()))

            if not provider:
                if attempt == self.max_retries - 1:
                    raise RuntimeError("No healthy LLM providers available")
                await asyncio.sleep(self.retry_delay * (2 ** attempt))  # Exponential backoff
                continue

            try:
                logger.debug(f"Attempting request with provider {provider.name} (attempt {attempt + 1})")
                response = await provider.generate_completion(prompt, **kwargs)
                return response, provider.name

            except Exception as e:
                logger.warning(f"Provider {provider.name} failed (attempt {attempt + 1}): {e}")
                provider.record_failure(e)

                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (2 ** attempt))  # Exponential backoff

        raise RuntimeError(f"All LLM providers failed after {self.max_retries} attempts")

    async def generate_completion(self,
                                prompt: str,
                                provider_name: Optional[str] = None,
                                **kwargs) -> Tuple[Dict[str, Any], str]:
        """
        Generate completion using smart routing.

        Args:
            prompt: The prompt to send to the LLM
            provider_name: Optional specific provider to use
            **kwargs: Additional arguments for the LLM

        Returns:
            Tuple of (response_dict, provider_name_used)
        """
        if provider_name and provider_name in self.providers:
            return await self._generate_with_specific_provider(prompt, provider_name, **kwargs)
        else:
            return await self._generate_with_routing(prompt, **kwargs)

    def enable_provider(self, provider_name: str):
        """Enable a provider."""
        if provider_name in self.providers:
            self.providers[provider_name].config.enabled = True
            logger.info(f"Enabled provider: {provider_name}")

    def disable_provider(self, provider_name: str):
        """Disable a provider."""
        if provider_name in self.providers:
            self.providers[provider_name].config.enabled = False
            logger.info(f"Disabled provider: {provider_name}")

    def set_routing_strategy(self, strategy: RoutingStrategy):
        """Change the routing strategy."""
        self.routing_strategy = strategy
        logger.info(f"Changed routing strategy to: {strategy.__class__.__name__}")


# Convenience functions for common configurations
def create_default_router() -> LLMRouter:
    """Create a router with default OpenAI configuration."""
    import os

    configs = []
    if os.getenv("OPENAI_API_KEY"):
        configs.append(ProviderConfig(
            name="openai",
            api_key=os.getenv("OPENAI_API_KEY"),
            model="gpt-3.5-turbo",
            priority=1
        ))

    if not configs:
        raise ValueError("No LLM API keys configured")

    return LLMRouter(configs)


def create_multi_provider_router() -> LLMRouter:
    """Create a router with multiple providers if available."""
    import os

    configs = []

    # OpenAI
    if os.getenv("OPENAI_API_KEY"):
        configs.append(ProviderConfig(
            name="openai",
            api_key=os.getenv("OPENAI_API_KEY"),
            model="gpt-3.5-turbo",
            priority=1
        ))

    # Anthropic
    if os.getenv("ANTHROPIC_API_KEY"):
        configs.append(ProviderConfig(
            name="anthropic",
            api_key=os.getenv("ANTHROPIC_API_KEY"),
            model="claude-3-haiku-20240307",
            priority=2
        ))

    # Google
    if os.getenv("GOOGLE_API_KEY"):
        configs.append(ProviderConfig(
            name="google",
            api_key=os.getenv("GOOGLE_API_KEY"),
            model="gemini-pro",
            priority=3
        ))

    if not configs:
        raise ValueError("No LLM API keys configured")

    return LLMRouter(configs, routing_strategy=PriorityRouting())