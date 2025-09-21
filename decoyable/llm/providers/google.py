"""
decoyable/llm/providers/google.py

Google Gemini provider implementation.
"""

import time
from typing import Any, Dict

import httpx

from ..base import (
    LLMProvider,
    ProviderAPIError,
    ProviderAuthError,
    ProviderConfig,
    ProviderRateLimitError,
    ProviderTimeoutError,
)


class GoogleProvider(LLMProvider):
    """Google Gemini provider implementation."""

    def __init__(self, config: ProviderConfig):
        super().__init__(config)
        if not config.api_key:
            raise ValueError("Google API key is required")

    async def generate_completion(self, prompt: str, **kwargs) -> Dict[str, Any]:
        """Generate completion using Google Gemini API."""
        start_time = time.time()

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                url = (
                    f"https://generativelanguage.googleapis.com/v1beta/models/"
                    f"{self.config.model}:generateContent?key={self.config.api_key}"
                )
                response = await client.post(
                    url,
                    headers={"Content-Type": "application/json"},
                    json={
                        "contents": [{"parts": [{"text": prompt}]}],
                        "generationConfig": {
                            "maxOutputTokens": kwargs.get("max_tokens", 500),
                            "temperature": kwargs.get("temperature", 0.1),
                        },
                    },
                )

                if response.status_code == 200:
                    result = response.json()
                    latency = time.time() - start_time
                    self.record_success(latency)
                    return result
                elif response.status_code == 429:
                    raise ProviderRateLimitError(f"Google rate limit exceeded: {response.text}")
                elif response.status_code == 401:
                    raise ProviderAuthError(f"Google authentication failed: {response.text}")
                else:
                    raise ProviderAPIError(f"Google API error {response.status_code}: {response.text}")

        except httpx.TimeoutException as e:
            raise ProviderTimeoutError("Google request timed out") from e
        except Exception as e:
            raise ProviderAPIError(f"Google request failed: {str(e)}") from e

    async def check_health(self) -> bool:
        """Check Google API health."""
        try:
            # Simple health check with a minimal prompt
            await self.generate_completion("Hello", max_tokens=10)
            return True
        except Exception:
            return False
