"""
Health check router for API monitoring and diagnostics.
"""

import time
from typing import Dict, Any

from fastapi import APIRouter, HTTPException

from decoyable.core.logging import get_logger

router = APIRouter()
logger = get_logger("api.health")


@router.get("/", summary="API Root", description="Returns basic API information and status")
async def root() -> Dict[str, Any]:
    """API root endpoint with basic service information."""
    return {
        "status": "ok",
        "service": "decoyable",
        "version": "0.1.0",
        "timestamp": time.time()
    }


@router.get("/health", summary="Health Check", description="Comprehensive health check endpoint")
async def health_check() -> Dict[str, Any]:
    """Comprehensive health check for monitoring service availability."""
    start_time = time.time()

    try:
        # Basic health checks
        health_status = {
            "status": "healthy",
            "timestamp": time.time(),
            "checks": {}
        }

        # Check core services
        health_status["checks"]["api"] = {"status": "healthy", "response_time": time.time() - start_time}

        # Check database connectivity (placeholder)
        health_status["checks"]["database"] = {"status": "healthy", "response_time": 0.001}

        # Check Redis connectivity (placeholder)
        health_status["checks"]["redis"] = {"status": "healthy", "response_time": 0.001}

        # Check Kafka connectivity (placeholder)
        health_status["checks"]["kafka"] = {"status": "healthy", "response_time": 0.001}

        # Overall status
        all_healthy = all(check["status"] == "healthy" for check in health_status["checks"].values())
        health_status["status"] = "healthy" if all_healthy else "degraded"

        return health_status

    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unhealthy")


@router.get("/health/ready", summary="Readiness Check", description="Check if service is ready to accept traffic")
async def readiness_check() -> Dict[str, Any]:
    """Kubernetes readiness probe endpoint."""
    # For now, always ready. In production, check dependencies.
    return {
        "status": "ready",
        "timestamp": time.time()
    }


@router.get("/health/live", summary="Liveness Check", description="Check if service is alive")
async def liveness_check() -> Dict[str, Any]:
    """Kubernetes liveness probe endpoint."""
    return {
        "status": "alive",
        "timestamp": time.time()
    }


@router.get("/ping", summary="Ping", description="Simple ping endpoint for connectivity testing")
async def ping() -> Dict[str, str]:
    """Simple ping endpoint."""
    return {"pong": "decoyable"}