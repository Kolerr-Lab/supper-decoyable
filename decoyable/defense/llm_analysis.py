"""
decoyable/defense/llm_analysis.py

LLM-powered attack analysis functions.
"""

import json
import logging
from typing import Any, Dict, Optional

from decoyable.llm import LLMRouter, create_default_router, create_multi_provider_router

from .adaptive_defense import adaptive_defense
from .patterns import ATTACK_PATTERNS

logger = logging.getLogger(__name__)

# Global LLM router instance
_llm_router: Optional[LLMRouter] = None


def get_llm_router() -> LLMRouter:
    """Get or create the global LLM router instance."""
    global _llm_router

    if _llm_router is None:
        try:
            _llm_router = create_multi_provider_router()
            logger.info("Initialized LLM router with multi-provider support")
        except ValueError:
            # Fallback to default router if multi-provider fails
            try:
                _llm_router = create_default_router()
                logger.info("Initialized LLM router with default OpenAI provider")
            except ValueError:
                logger.warning("No LLM providers configured, LLM analysis will be unavailable")
                raise RuntimeError("No LLM providers available")

    return _llm_router


async def analyze_attack_with_llm(attack_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze attack using LLM with smart routing and failover.

    Args:
        attack_data: Attack log data

    Returns:
        Analysis result with attack_type, confidence, recommended_action
    """
    try:
        router = get_llm_router()
    except RuntimeError:
        # No LLM providers available, fallback to pattern-based analysis
        logger.info("No LLM providers available, using pattern-based analysis")
        return await analyze_attack_patterns(attack_data)

    try:
        prompt = f"""
Analyze this HTTP request for potential cyber attack patterns. Respond with JSON only.

Request Details:
- Method: {attack_data.get('method', 'UNKNOWN')}
- Path: {attack_data.get('path', 'UNKNOWN')}
- Headers: {json.dumps(attack_data.get('headers', {}), indent=2)}
- Body: {attack_data.get('body', 'None')[:500]}...
- Query Params: {json.dumps(attack_data.get('query_params', {}), indent=2)}
- User Agent: {attack_data.get('user_agent', 'None')}

Classify the attack type and provide:
1. attack_type: (SQLi, XSS, command_injection, path_traversal, brute_force, reconnaissance, unknown)
2. confidence: (0.0-1.0)
3. recommended_action: (block_ip, monitor, log_only, ignore)
4. explanation: brief explanation
5. severity: (critical, high, medium, low, info)
6. indicators: list of suspicious patterns found

JSON Response:
"""

        response, provider_used = await router.generate_completion(
            prompt,
            max_tokens=500,
            temperature=0.1
        )

        logger.debug(f"LLM analysis completed using provider: {provider_used}")

        # Parse JSON response
        try:
            content = response["choices"][0]["message"]["content"]
            analysis = json.loads(content)
            return analysis
        except (KeyError, json.JSONDecodeError) as e:
            logger.error(f"Failed to parse LLM response: {e}")
            return await analyze_attack_patterns(attack_data)

    except Exception as exc:
        logger.error(f"LLM analysis failed: {exc}")
        return await analyze_attack_patterns(attack_data)


async def analyze_attack_patterns(attack_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Fallback pattern-based attack analysis.

    Args:
        attack_data: Attack log data

    Returns:
        Analysis result
    """
    import re

    # Combine all text for analysis
    text_to_analyze = ""
    text_to_analyze += attack_data.get("path", "")
    text_to_analyze += " " + json.dumps(attack_data.get("headers", {}))
    text_to_analyze += " " + str(attack_data.get("body", ""))
    text_to_analyze += " " + json.dumps(attack_data.get("query_params", {}))

    # Check against patterns with prioritization
    all_patterns = adaptive_defense.get_all_patterns()

    # Priority order: most dangerous to least dangerous
    priority_order = [
        "sqli",
        "command_injection",
        "xss",
        "path_traversal",
        "brute_force",
        "reconnaissance",
    ]

    matches = {}
    max_confidence = 0.0
    best_attack_type = "unknown"
    best_indicators = []

    for attack_type in priority_order:
        if attack_type not in all_patterns:
            continue

        patterns = all_patterns[attack_type]
        matches[attack_type] = []

        for pattern in patterns:
            try:
                if re.search(pattern, text_to_analyze, re.IGNORECASE | re.MULTILINE):
                    matches[attack_type].append(pattern)
            except re.error:
                continue  # Skip invalid patterns

        if matches[attack_type]:
            # Calculate confidence based on pattern strength and count
            pattern_count = len(matches[attack_type])

            # Base confidence on pattern matches
            if attack_type in ["sqli", "command_injection"]:
                confidence = min(0.4 + (pattern_count * 0.2), 0.95)
            elif attack_type in ["xss", "path_traversal"]:
                confidence = min(0.35 + (pattern_count * 0.15), 0.85)
            elif attack_type == "brute_force":
                confidence = min(0.2 + (pattern_count * 0.1), 0.7)
            else:  # reconnaissance
                confidence = min(0.15 + (pattern_count * 0.1), 0.6)

            # If this attack type has higher confidence, use it
            if confidence > max_confidence:
                max_confidence = confidence
                best_attack_type = attack_type
                best_indicators = matches[attack_type]

    # Determine action and severity based on attack type and confidence
    if best_attack_type == "sqli" and max_confidence > 0.4:
        action = "block_ip"
        severity = "critical"
    elif best_attack_type == "command_injection" and max_confidence > 0.4:
        action = "block_ip"
        severity = "critical"
    elif best_attack_type == "xss" and max_confidence > 0.3:
        action = "block_ip"
        severity = "high"
    elif best_attack_type == "path_traversal" and max_confidence > 0.3:
        action = "block_ip"
        severity = "high"
    elif best_attack_type == "brute_force" and max_confidence > 0.4:
        action = "block_ip"
        severity = "medium"
    elif best_attack_type == "reconnaissance":
        action = "monitor"
        severity = "low"
    else:
        action = "log_only"
        severity = "info"
        max_confidence = 0.0
        best_attack_type = "unknown"
        best_indicators = []

    return {
        "attack_type": best_attack_type,
        "confidence": max_confidence,
        "recommended_action": action,
        "explanation": f"Pattern-based analysis detected {best_attack_type}",
        "severity": severity,
        "indicators": best_indicators,
    }