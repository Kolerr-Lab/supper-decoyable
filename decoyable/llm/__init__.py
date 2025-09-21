"""
decoyable.llm

Smart LLM routing engine with failover capabilities for DECOYABLE.
Provides unified interface to multiple LLM providers with automatic failover,
load balancing, and comprehensive error handling.
"""

from .base import (
    LLMProvider,
    ProviderConfig,
    ProviderStatus,
    LLMProviderError,
    ProviderRateLimitError,
    ProviderTimeoutError,
    ProviderAuthError,
    ProviderAPIError,
)
from .providers import (
    OpenAIProvider,
    AnthropicProvider,
    GoogleProvider,
)
from .router import (
    LLMRouter,
    RoutingStrategy,
    PriorityRouting,
    LoadBalancingRouting,
    FailoverRouting,
    create_default_router,
    create_multi_provider_router,
)

__all__ = [
    # Providers
    "LLMProvider",
    "OpenAIProvider",
    "AnthropicProvider",
    "GoogleProvider",
    "ProviderConfig",
    "ProviderStatus",
    "LLMProviderError",
    "ProviderRateLimitError",
    "ProviderTimeoutError",
    "ProviderAuthError",
    "ProviderAPIError",

    # Router
    "LLMRouter",
    "RoutingStrategy",
    "PriorityRouting",
    "LoadBalancingRouting",
    "FailoverRouting",
    "create_default_router",
    "create_multi_provider_router",
]