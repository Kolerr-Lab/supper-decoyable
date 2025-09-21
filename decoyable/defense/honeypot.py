"""
decoyable/defense/honeypot.py

Active cyber defense honeypot endpoints for DECOYABLE.
Provides decoy endpoints that capture attacker requests and trigger defensive actions.
"""

import asyncio
import json
import logging
import os
import time
from datetime import datetime
from typing import Any, Dict, Optional

import httpx
from fastapi import APIRouter, BackgroundTasks, Request, Response
from pydantic import BaseModel

from decoyable.defense.analysis import analyze_attack_async

# Configure logging
logger = logging.getLogger(__name__)

# Environment variables
SECURITY_TEAM_ENDPOINT = os.getenv("SECURITY_TEAM_ENDPOINT", "")
DECOY_PORTS = os.getenv("DECOY_PORTS", "9001,2222").split(",")


# Create router
router = APIRouter(prefix="/decoy", tags=["honeypot"])


async def forward_alert(data: Dict[str, Any]) -> None:
    """
    Forward attack alerts to security team endpoint.

    This is best-effort and will not raise on failure.
    """
    endpoint = os.getenv("SECURITY_TEAM_ENDPOINT", "")
    if not endpoint:
        logger.debug("SECURITY_TEAM_ENDPOINT not configured; skipping forward_alert")
        return

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(endpoint, json=data, headers={"Content-Type": "application/json"})
            if resp.status_code >= 200 and resp.status_code < 300:
                logger.info("Alert forwarded to security endpoint")
            else:
                logger.error(f"Security endpoint returned {resp.status_code}: {resp.text}")
    except Exception as exc:
        logger.error(f"Failed to forward alert: {exc}")


async def block_ip(ip: str) -> None:
    """
    Block an IP address using system firewall (iptables).

    In non-Linux environments iptables is likely unavailable; function will log and return.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "iptables",
            "-A",
            "INPUT",
            "-s",
            ip,
            "-j",
            "DROP",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.wait(), timeout=8.0)
        if proc.returncode == 0:
            logger.info(f"Blocked IP {ip} via iptables")
        else:
            stderr = await proc.stderr.read()
            logger.error(f"iptables failed for {ip}: {stderr}")
    except FileNotFoundError:
        logger.warning("iptables not found; skipping IP block")
    except asyncio.TimeoutError:
        logger.error(f"Timeout while blocking IP {ip}")
    except Exception as exc:
        logger.error(f"Error blocking IP {ip}: {exc}")


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


@router.get("/status")
async def honeypot_status() -> Dict[str, Any]:
    return {
        "status": "active",
        "decoy_ports": DECOY_PORTS,
        "security_endpoint": bool(SECURITY_TEAM_ENDPOINT),
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/logs/recent")
async def recent_logs(limit: int = 10) -> Dict[str, Any]:
    return {"logs": [], "limit": limit, "message": "TODO: integrate knowledge base"}


@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def honeypot_endpoint(request: Request, background_tasks: BackgroundTasks, path: str) -> Response:
    start = time.time()
    full_path = f"/decoy/{path}"
    lower_path = full_path.lower()
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
        logger.warning(f"Slow honeypot response: {elapsed_ms:.2f}ms for {request.url.path}")

    # background processing
    background_tasks.add_task(process_attack_async, request)
    return response


async def process_attack_async(request: Request) -> None:
    try:
        attack_log = await capture_request(request)
        logger.warning(f"Honeypot triggered: {attack_log.method} {attack_log.path} from {attack_log.ip_address}")

        analysis_result = await analyze_attack_async(attack_log.dict())

        attack_log.attack_type = analysis_result.get("attack_type")
        attack_log.confidence = analysis_result.get("confidence")
        attack_log.recommended_action = analysis_result.get("recommended_action")

        # forward alert (best effort)
        await forward_alert(attack_log.dict())

        # block if recommended
        if attack_log.recommended_action in ("block", "block_ip"):
            await block_ip(attack_log.ip_address)

    except Exception as exc:
        logger.error(f"Error processing honeypot attack: {exc}")
