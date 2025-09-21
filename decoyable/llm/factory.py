"""
decoyable/llm/providers.py

LLM provider factory and utilities.
Imports provider implementations from separate modules for better maintainability.
"""

from .base import LLMProvider, ProviderConfig
from .providers import AnthropicProvider, GoogleProvider, OpenAIProvider

# Provider factory
PROVIDER_CLASSES = {
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "google": GoogleProvider,
}


def create_provider(provider_type: str, config: ProviderConfig) -> LLMProvider:
    """Create an LLM provider instance."""
    if provider_type not in PROVIDER_CLASSES:
        raise ValueError(f"Unknown provider type: {provider_type}")

    return PROVIDER_CLASSES[provider_type](config)
