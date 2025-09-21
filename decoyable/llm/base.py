"""
decoyable/llm/base.py

Base classes and common functionality for LLM providers.
"""

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class ProviderStatus(Enum):
    """Status of an LLM provider."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    DISABLED = "disabled"


class LLMProviderError(Exception):
    """Base exception for LLM provider errors."""
    pass


class ProviderRateLimitError(LLMProviderError):
    """Raised when provider rate limit is exceeded."""
    pass


class ProviderTimeoutError(LLMProviderError):
    """Raised when provider request times out."""
    pass


class ProviderAuthError(LLMProviderError):
    """Raised when provider authentication fails."""
    pass


class ProviderAPIError(LLMProviderError):
    """Raised when provider API returns an error."""
    pass


@dataclass
class ProviderConfig:
    """Configuration for an LLM provider."""
    name: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    model: str = "gpt-3.5-turbo"
    timeout: float = 30.0
    max_retries: int = 3
    rate_limit_requests: int = 100
    rate_limit_window: int = 60  # seconds
    enabled: bool = True
    priority: int = 1  # Lower number = higher priority


@dataclass
class ProviderMetrics:
    """Metrics for provider performance tracking."""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_latency: float = 0.0
    last_request_time: Optional[float] = None
    consecutive_failures: int = 0
    rate_limit_hits: int = 0


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    def __init__(self, config: ProviderConfig):
        self.config = config
        self.metrics = ProviderMetrics()
        self._status = ProviderStatus.HEALTHY
        self._circuit_breaker_failures = 0
        self._circuit_breaker_last_failure = 0
        self._circuit_breaker_timeout = 60  # seconds

    @property
    def status(self) -> ProviderStatus:
        """Get current provider status."""
        return self._status

    @property
    def name(self) -> str:
        """Get provider name."""
        return self.config.name

    def is_healthy(self) -> bool:
        """Check if provider is healthy."""
        return self._status in [ProviderStatus.HEALTHY, ProviderStatus.DEGRADED]

    def should_attempt_request(self) -> bool:
        """Check if we should attempt a request (circuit breaker logic)."""
        if self._status == ProviderStatus.DISABLED:
            return False

        # Circuit breaker: if too many failures recently, temporarily disable
        if self._circuit_breaker_failures >= 5:
            if time.time() - self._circuit_breaker_last_failure < self._circuit_breaker_timeout:
                return False
            else:
                # Reset circuit breaker
                self._circuit_breaker_failures = 0

        return True

    def record_success(self, latency: float):
        """Record a successful request."""
        self.metrics.total_requests += 1
        self.metrics.successful_requests += 1
        self.metrics.total_latency += latency
        self.metrics.last_request_time = time.time()
        self.metrics.consecutive_failures = 0
        self._status = ProviderStatus.HEALTHY

    def record_failure(self, error: Exception):
        """Record a failed request."""
        self.metrics.total_requests += 1
        self.metrics.failed_requests += 1
        self.metrics.consecutive_failures += 1
        self.metrics.last_request_time = time.time()

        # Update circuit breaker
        self._circuit_breaker_failures += 1
        self._circuit_breaker_last_failure = time.time()

        # Update status based on failure pattern
        if self.metrics.consecutive_failures >= 5:
            self._status = ProviderStatus.UNHEALTHY
        elif self.metrics.consecutive_failures >= 2:
            self._status = ProviderStatus.DEGRADED

        # Classify error types
        if isinstance(error, ProviderRateLimitError):
            self.metrics.rate_limit_hits += 1

    @abstractmethod
    async def generate_completion(self, prompt: str, **kwargs) -> Dict[str, Any]:
        """Generate completion from the LLM provider."""
        pass

    @abstractmethod
    async def check_health(self) -> bool:
        """Check if the provider is healthy and accessible."""
        pass