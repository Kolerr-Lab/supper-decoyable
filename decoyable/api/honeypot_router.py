"""
Honeypot API Router

Refactored FastAPI router for honeypot endpoints with service registry integration.
Provides clean dependency injection and modular design for active defense.
"""

import json
import time
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Request, Response
from pydantic import BaseModel

from decoyable.core.registry import get_service_registry

# Create router
router = APIRouter(prefix="/api/v1/honeypot", tags=["honeypot"])


class AttackLog(BaseModel):
    timestamp: str
    ip_address: str
    method: str
    path: str
    headers: Dict[str, str]
    body: Optional[str] = None
    user_agent: Optional[str] = None
    query_params: Dict[str, Any] = {}
    attack_type: Optional[str] = None
    confidence: Optional[float] = None
    recommended_action: Optional[str] = None


def get_client_ip(request: Request) -> str:
    """Extract client IP respecting proxy headers."""
    # Check common header names (lowercase in tests)
    xff = request.headers.get("x-forwarded-for") or request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()

    xri = request.headers.get("x-real-ip") or request.headers.get("X-Real-IP")
    if xri:
        return xri

    return request.client.host if request.client else "unknown"


async def capture_request(request: Request) -> AttackLog:
    """Capture request data into an AttackLog."""
    body = None
    try:
        body_bytes = await request.body()
        if body_bytes:
            body = body_bytes.decode("utf-8", errors="ignore")
    except Exception:
        body = "<binary or unreadable>"

    headers = dict(request.headers)

    return AttackLog(
        timestamp=datetime.utcnow().isoformat(),
        ip_address=get_client_ip(request),
        method=request.method,
        path=request.url.path,
        headers=headers,
        body=body,
        user_agent=headers.get("user-agent"),
        query_params=dict(request.query_params),
    )


async def get_honeypot_service() -> Any:
    """Dependency to get honeypot service from registry."""
    registry = get_service_registry()
    return registry.get_by_name("honeypot_service")


@router.get("/status")
async def honeypot_status(honeypot_service=Depends(get_honeypot_service)) -> Dict[str, Any]:
    """Get honeypot service status."""
    return await honeypot_service.get_honeypot_status()


@router.get("/health")
async def honeypot_health(honeypot_service=Depends(get_honeypot_service)) -> Dict[str, Any]:
    """Get honeypot service health check."""
    return await honeypot_service.health_check()


@router.get("/attacks")
async def get_recent_attacks(limit: int = 10, honeypot_service=Depends(get_honeypot_service)) -> Dict[str, Any]:
    """Get recent honeypot attacks."""
    attacks = await honeypot_service.get_recent_attacks(limit)
    return {"attacks": attacks, "count": len(attacks), "limit": limit}


@router.get("/patterns")
async def get_attack_patterns(honeypot_service=Depends(get_honeypot_service)) -> Dict[str, Any]:
    """Get attack patterns."""
    patterns = await honeypot_service.get_attack_patterns()
    return {
        "patterns": patterns,
        "pattern_types": len(patterns),
        "total_patterns": sum(len(pats) for pats in patterns.values()),
    }


@router.post("/block/{ip_address}")
async def block_ip(ip_address: str, honeypot_service=Depends(get_honeypot_service)) -> Dict[str, Any]:
    """Block an IP address."""
    success = await honeypot_service.block_ip(ip_address)
    return {"success": success, "ip_address": ip_address, "action": "blocked" if success else "failed"}


@router.post("/decoy")
async def add_decoy_endpoint(endpoint: str, honeypot_service=Depends(get_honeypot_service)) -> Dict[str, Any]:
    """Add a decoy endpoint."""
    await honeypot_service.add_decoy_endpoint(endpoint)
    return {"success": True, "endpoint": endpoint, "action": "added"}


# Legacy decoy endpoints for backward compatibility
@router.api_route("/decoy/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def legacy_honeypot_endpoint(
    request: Request, background_tasks: BackgroundTasks, path: str, honeypot_service=Depends(get_honeypot_service)
) -> Response:
    """Legacy honeypot endpoint for backward compatibility."""
    start = time.time()
    full_path = f"/decoy/{path}"
    lower_path = full_path.lower()

    # Generate appropriate response based on path
    if lower_path.endswith((".json", ".api")) or path.endswith((".json", ".api")):
        content = json.dumps({"status": "ok", "message": "API endpoint active"})
        media_type = "application/json"
    elif "wsdl" in lower_path or lower_path.endswith((".xml",)) or path.endswith((".xml", ".wsdl")):
        content = '<?xml version="1.0"?><response><status>active</status></response>'
        media_type = "application/xml"
    elif "admin" in full_path.lower() or "login" in full_path.lower():
        content = "<html><body><h1>Admin Panel</h1><p>Access granted</p></body></html>"
        media_type = "text/html"
    else:
        content = "Service available"
        media_type = "text/plain"

    response = Response(content=content, media_type=media_type)
    elapsed_ms = (time.time() - start) * 1000

    if elapsed_ms > 50:
        # Log slow responses but don't fail the request
        import logging

        logger = logging.getLogger(__name__)
        logger.warning(f"Slow honeypot response: {elapsed_ms:.2f}ms for {request.url.path}")

    # Process attack in background
    background_tasks.add_task(process_attack_background, request, honeypot_service)

    return response


async def process_attack_background(request: Request, honeypot_service) -> None:
    """Process attack in background."""
    try:
        attack_log = await capture_request(request)
        attack_data = attack_log.dict()

        # Process through honeypot service
        result = await honeypot_service.process_attack(attack_data)

        # Log the result
        import logging

        logger = logging.getLogger(__name__)
        logger.info(f"Processed honeypot attack: {result}")

    except Exception as exc:
        import logging

        logger = logging.getLogger(__name__)
        logger.error(f"Error processing honeypot attack: {exc}")
