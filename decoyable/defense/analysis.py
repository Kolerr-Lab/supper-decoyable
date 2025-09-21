"""
decoyable/defense/analysis.py

Main analysis logic and API endpoints for DECOYABLE defense system.
"""

import json
import logging
import os
import re
from typing import Any, Dict

from fastapi import APIRouter

from .adaptive_defense import adaptive_defense
from .knowledge_base import knowledge_base
from .llm_analysis import analyze_attack_with_llm

# Configure logging
logger = logging.getLogger(__name__)

# Environment variables
KNOWLEDGE_DB_PATH = os.getenv("KNOWLEDGE_DB_PATH", "decoyable_knowledge.db")


async def analyze_attack_async(attack_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for attack analysis.

    Args:
        attack_data: Attack log data

    Returns:
        Analysis result
    """
    # Use LLM if available, otherwise pattern matching
    analysis_result = await analyze_attack_with_llm(attack_data)

    # Store in knowledge base
    try:
        attack_id = knowledge_base.store_analysis(attack_data, analysis_result)
        analysis_result["attack_id"] = attack_id
    except Exception as exc:
        logger.error(f"Failed to store analysis: {exc}")

    # Apply adaptive defense
    await apply_adaptive_defense(attack_data, analysis_result)

    return analysis_result


async def apply_adaptive_defense(attack_data: Dict[str, Any], analysis_result: Dict[str, Any]) -> None:
    """
    Apply adaptive defense based on analysis results.

    Args:
        attack_data: Original attack data
        analysis_result: Analysis results
    """
    attack_type = analysis_result.get("attack_type", "unknown")
    confidence = analysis_result.get("confidence", 0.0)
    action = analysis_result.get("recommended_action", "log_only")

    # Extract patterns for future detection
    if confidence > 0.7 and attack_type != "unknown":
        # Add suspicious path patterns
        path = attack_data.get("path", "")
        if len(path) > 10 and "?" in path:  # Has query parameters
            # Extract potential attack patterns from path
            if "=" in path:
                params = path.split("?")[1] if "?" in path else path
                for param in params.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        if len(value) > 20:  # Long suspicious values
                            pattern = re.escape(value[:50])  # First 50 chars
                            adaptive_defense.add_pattern(attack_type, pattern)

    # Add decoy endpoints based on reconnaissance
    if attack_type == "reconnaissance" and confidence > 0.5:
        path = attack_data.get("path", "")
        if path.startswith("/"):
            # Create similar decoy endpoints
            decoy_variants = [
                path.replace(".php", ".bak"),
                path.replace(".php", ".old"),
                path + ".backup",
                path + "~",
            ]
            for decoy in decoy_variants:
                if decoy not in adaptive_defense.decoy_endpoints:
                    adaptive_defense.add_decoy_endpoint(decoy)

    # IP blocking based on recommended action
    if action == "block_ip":
        ip = attack_data.get("ip_address")
        if ip:
            adaptive_defense.block_ip(ip)


# FastAPI router for analysis endpoints

router = APIRouter(prefix="/analysis", tags=["analysis"])


@router.get("/recent")
async def get_recent_analyses(limit: int = 10) -> Dict[str, Any]:
    """Get recent attack analyses."""
    try:
        analyses = knowledge_base.get_recent_analyses(limit)
        return {"analyses": analyses, "count": len(analyses), "limit": limit}
    except Exception as exc:
        logger.error(f"Failed to get recent analyses: {exc}")
        return {"error": str(exc)}


@router.get("/stats")
async def get_attack_stats(days: int = 7) -> Dict[str, Any]:
    """Get attack statistics."""
    try:
        stats = knowledge_base.get_attack_stats(days)
        return stats
    except Exception as exc:
        logger.error(f"Failed to get attack stats: {exc}")
        return {"error": str(exc)}


@router.post("/feedback/{attack_id}")
async def add_feedback(attack_id: int, feedback_data: Dict[str, str]) -> Dict[str, Any]:
    """Add feedback to an attack analysis."""
    try:
        feedback = feedback_data.get("feedback", "")
        success = knowledge_base.update_feedback(attack_id, feedback)
        return {"success": success, "attack_id": attack_id}
    except Exception as exc:
        logger.error(f"Failed to add feedback: {exc}")
        return {"error": str(exc)}


@router.get("/llm-status")
async def get_llm_status() -> Dict[str, Any]:
    """Get LLM router and provider status."""
    try:
        from .llm_analysis import get_llm_router

        router = get_llm_router()
        status = router.get_provider_status()
        return {
            "router_status": "active",
            "providers": status,
            "routing_strategy": router.routing_strategy.__class__.__name__
        }
    except RuntimeError as e:
        return {
            "router_status": "inactive",
            "error": str(e),
            "providers": {}
        }
    except Exception as exc:
        logger.error(f"Failed to get LLM status: {exc}")
        return {"error": str(exc)}


@router.get("/patterns")
async def get_patterns() -> Dict[str, Any]:
    """Get current attack detection patterns."""
    from .patterns import ATTACK_PATTERNS

    return {
        "static_patterns": ATTACK_PATTERNS,
        "dynamic_patterns": adaptive_defense.dynamic_patterns,
        "blocked_ips": list(adaptive_defense.blocked_ips),
        "decoy_endpoints": list(adaptive_defense.decoy_endpoints),
    }
