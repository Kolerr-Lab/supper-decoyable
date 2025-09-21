"""
decoyable/llm/providers/anthropic.py

Anthropic Claude provider implementation.
"""

import time
from typing import Any, Dict

import httpx

from ..base import LLMProvider, ProviderAPIError, ProviderAuthError, ProviderConfig, ProviderRateLimitError, ProviderTimeoutError


class AnthropicProvider(LLMProvider):
    """Anthropic Claude provider implementation."""

    def __init__(self, config: ProviderConfig):
        super().__init__(config)
        if not config.api_key:
            raise ValueError("Anthropic API key is required")

    async def generate_completion(self, prompt: str, **kwargs) -> Dict[str, Any]:
        """Generate completion using Anthropic API."""
        start_time = time.time()

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                response = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": self.config.api_key,
                        "anthropic-version": "2023-06-01",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.config.model,
                        "max_tokens": kwargs.get("max_tokens", 500),
                        "temperature": kwargs.get("temperature", 0.1),
                        "messages": [{"role": "user", "content": prompt}],
                    },
                )

                if response.status_code == 200:
                    result = response.json()
                    latency = time.time() - start_time
                    self.record_success(latency)
                    return result
                elif response.status_code == 429:
                    raise ProviderRateLimitError(f"Anthropic rate limit exceeded: {response.text}")
                elif response.status_code == 401:
                    raise ProviderAuthError(f"Anthropic authentication failed: {response.text}")
                else:
                    raise ProviderAPIError(f"Anthropic API error {response.status_code}: {response.text}")

        except httpx.TimeoutException:
            raise ProviderTimeoutError("Anthropic request timed out")
        except Exception as e:
            raise ProviderAPIError(f"Anthropic request failed: {str(e)}")

    async def check_health(self) -> bool:
        """Check Anthropic API health."""
        try:
            # Simple health check with a minimal prompt
            await self.generate_completion("Hello", max_tokens=10)
            return True
        except Exception:
            return False