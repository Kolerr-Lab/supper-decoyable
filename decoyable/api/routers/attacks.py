"""
Attacks router for attack event monitoring and management.
"""

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Query

from decoyable.core.logging import get_logger

router = APIRouter()
logger = get_logger("api.attacks")


@router.get("/attacks", summary="Get Attack Events", description="Retrieve recent attack events and statistics")
async def get_attacks(
    limit: int = Query(100, description="Maximum number of attacks to return", ge=1, le=1000),
    offset: int = Query(0, description="Number of attacks to skip", ge=0),
    attack_type: Optional[str] = Query(None, description="Filter by attack type"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
) -> Dict[str, Any]:
    """
    Get recent attack events from the system.

    Returns attack events with filtering and pagination support.
    """
    try:
        # Import here to avoid circular imports
        from decoyable.core.registry import AttackRegistry

        registry = AttackRegistry()
        attack_types = registry.get_attack_types()

        # Mock attack data for testing - in real implementation this would come from database/Kafka
        mock_attacks = [
            {
                "id": "attack_001",
                "type": "sql_injection",
                "source_ip": "192.168.1.100",
                "timestamp": "2025-01-15T10:30:00Z",
                "severity": "high",
                "description": "SQL injection attempt detected",
                "details": {
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "payload": "'; DROP TABLE users; --",
                    "endpoint": "/api/search",
                },
            },
            {
                "id": "attack_002",
                "type": "xss",
                "source_ip": "10.0.0.50",
                "timestamp": "2025-01-15T10:25:00Z",
                "severity": "medium",
                "description": "Cross-site scripting attempt",
                "details": {
                    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
                    "payload": "<script>alert('xss')</script>",
                    "endpoint": "/contact",
                },
            },
            {
                "id": "attack_003",
                "type": "brute_force",
                "source_ip": "203.0.113.1",
                "timestamp": "2025-01-15T10:20:00Z",
                "severity": "low",
                "description": "Brute force login attempt",
                "details": {"attempts": 25, "time_window": "5 minutes", "target_user": "admin"},
            },
        ]

        # Apply filters
        filtered_attacks = mock_attacks

        if attack_type:
            filtered_attacks = [a for a in filtered_attacks if a["type"] == attack_type]

        if severity:
            filtered_attacks = [a for a in filtered_attacks if a["severity"] == severity]

        # Apply pagination
        paginated_attacks = filtered_attacks[offset : offset + limit]

        return {
            "status": "success",
            "attacks": paginated_attacks,
            "total": len(filtered_attacks),
            "returned": len(paginated_attacks),
            "limit": limit,
            "offset": offset,
            "filters": {"attack_type": attack_type, "severity": severity},
            "attack_types": list(attack_types.keys()),
        }

    except Exception as e:
        logger.exception("Error retrieving attacks")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve attacks: {str(e)}")


@router.get(
    "/attacks/{attack_id}",
    summary="Get Attack Details",
    description="Retrieve detailed information about a specific attack",
)
async def get_attack_details(attack_id: str) -> Dict[str, Any]:
    """Get detailed information about a specific attack event."""
    try:
        # Mock detailed attack data
        mock_attack_details = {
            "attack_001": {
                "id": "attack_001",
                "type": "sql_injection",
                "source_ip": "192.168.1.100",
                "timestamp": "2025-01-15T10:30:00Z",
                "severity": "high",
                "description": "SQL injection attempt detected",
                "details": {
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "payload": "'; DROP TABLE users; --",
                    "endpoint": "/api/search",
                    "method": "POST",
                    "headers": {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    },
                    "query_params": {"q": "test"},
                    "response_code": 500,
                    "response_time": 0.234,
                },
                "analysis": {
                    "confidence": 0.95,
                    "pattern_matched": "sql_injection_union_select",
                    "potential_impact": "Data exfiltration",
                    "recommended_action": "Block IP, review database logs",
                },
            }
        }

        if attack_id not in mock_attack_details:
            raise HTTPException(status_code=404, detail=f"Attack {attack_id} not found")

        return {"status": "success", "attack": mock_attack_details[attack_id]}

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error retrieving attack details for {attack_id}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve attack details: {str(e)}")


@router.get("/attacks/stats", summary="Get Attack Statistics", description="Retrieve attack statistics and trends")
async def get_attack_stats(hours: int = Query(24, description="Time window in hours", ge=1, le=168)) -> Dict[str, Any]:
    """Get attack statistics and trends for the specified time window."""
    try:
        # Mock statistics data
        mock_stats = {
            "time_window_hours": hours,
            "total_attacks": 47,
            "attacks_by_type": {
                "sql_injection": 12,
                "xss": 8,
                "brute_force": 15,
                "directory_traversal": 5,
                "command_injection": 7,
            },
            "attacks_by_severity": {"critical": 3, "high": 18, "medium": 16, "low": 10},
            "top_source_ips": [
                {"ip": "192.168.1.100", "count": 8},
                {"ip": "10.0.0.50", "count": 6},
                {"ip": "203.0.113.1", "count": 5},
            ],
            "attacks_over_time": [
                {"timestamp": "2025-01-15T06:00:00Z", "count": 2},
                {"timestamp": "2025-01-15T07:00:00Z", "count": 5},
                {"timestamp": "2025-01-15T08:00:00Z", "count": 8},
                {"timestamp": "2025-01-15T09:00:00Z", "count": 12},
                {"timestamp": "2025-01-15T10:00:00Z", "count": 20},
            ],
        }

        return {"status": "success", "stats": mock_stats}

    except Exception as e:
        logger.exception("Error retrieving attack statistics")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve attack statistics: {str(e)}")
