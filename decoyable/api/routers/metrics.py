"""
Metrics router for Prometheus monitoring and metrics.
"""

from fastapi import APIRouter, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

router = APIRouter()


@router.get("/metrics", summary="Prometheus Metrics", description="Exposes Prometheus metrics for monitoring and alerting")
async def metrics() -> Response:
    """Return Prometheus metrics for monitoring."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)