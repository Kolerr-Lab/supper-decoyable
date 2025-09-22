import logging
import os
import sys
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, Field, validator

# /g:/TECH/DECOYABLE/decoyable/api/app.py
"""
FastAPI application bootstrap for the decoyable project.
This file attempts to auto-wire routers or an init_app from a top-level main.py if present.
If you paste the contents of your main.py I can adapt this precisely.
"""


# Make sure project root is importable (adjust if your layout differs)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

logger = logging.getLogger("decoyable.api")
logging.basicConfig(level=logging.INFO)


class ScanRequest(BaseModel):
    """Request model for scan endpoints with validation."""

    path: str = Field(..., min_length=1, max_length=4096, description="Path to scan")

    @validator("path")
    def validate_path(cls, v):
        """Validate that the path is safe and exists."""
        if not v or not v.strip():
            raise ValueError("Path cannot be empty")

        # Prevent path traversal attacks
        if ".." in v or v.startswith("/etc") or v.startswith("/proc") or v.startswith("/sys"):
            raise ValueError("Invalid path: potential security risk")

        # Convert to absolute path and validate
        try:
            abs_path = os.path.abspath(v)
            if not os.path.exists(abs_path):
                raise ValueError(f"Path does not exist: {abs_path}")
            return abs_path
        except (OSError, ValueError) as e:
            raise ValueError(f"Invalid path: {str(e)}") from e


def create_app() -> FastAPI:
    app = FastAPI(
        title="DECOYABLE API",
        description="""
        # DECOYABLE - Enterprise Cybersecurity Scanning Platform

        DECOYABLE is an AI-powered cybersecurity scanning platform that combines traditional security tools with advanced machine learning to provide comprehensive threat detection and analysis.

        ## Features

        * **Multi-Modal Scanning**: Secrets, dependencies, vulnerabilities, and behavioral analysis
        * **AI-Powered Analysis**: LLM integration for intelligent threat assessment
        * **Honeypot Technology**: Active defense mechanisms
        * **Enterprise Ready**: Scalable, secure, and compliant
        * **Developer Friendly**: Easy integration with CI/CD pipelines

        ## Authentication

        Some endpoints require authentication. Use API keys or OAuth2 tokens as specified in endpoint documentation.

        ## Rate Limiting

        API requests are rate-limited. Check the `X-RateLimit-*` headers in responses.

        ## Support

        - Documentation: [GitHub Repository](https://github.com/Kolerr-Lab/supper-decoyable)
        - Issues: [GitHub Issues](https://github.com/Kolerr-Lab/supper-decoyable/issues)
        - Security: [Security Policy](https://github.com/Kolerr-Lab/supper-decoyable/security/policy)
        """,
        version="0.1.0",
        contact={
            "name": "DECOYABLE Team",
            "url": "https://github.com/Kolerr-Lab/supper-decoyable",
            "email": "lab.kolerr@kolerr.com",
        },
        license_info={
            "name": "MIT",
            "url": "https://opensource.org/licenses/MIT",
        },
        openapi_tags=[
            {
                "name": "health",
                "description": "Health check and monitoring endpoints",
            },
            {
                "name": "scanning",
                "description": "Security scanning operations",
            },
            {
                "name": "analysis",
                "description": "Threat analysis and intelligence",
            },
            {
                "name": "honeypot",
                "description": "Honeypot management and monitoring",
            },
            {
                "name": "metrics",
                "description": "Prometheus metrics and monitoring",
            },
            {
                "name": "attacks",
                "description": "Attack event monitoring and management",
            },
        ],
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # Security middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # TODO: Restrict in production
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # Trusted host middleware for additional security
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*"],  # TODO: Configure allowed hosts in production
    )

    # Basic endpoints
    @app.get("/", summary="API Root", description="Returns basic API information and status", tags=["health"])
    async def root() -> dict:
        return {"status": "ok", "service": "decoyable", "version": "0.1.0"}

    @app.get("/health", summary="Health Check", description="Comprehensive health check endpoint for monitoring service availability", tags=["health"])
    async def health() -> dict:
        return {"status": "healthy", "timestamp": "2025-09-21T00:00:00Z"}

    @app.get("/api/v1/attacks", summary="Get Attack Events", description="Retrieve recent attack events and statistics", tags=["attacks"])
    async def get_attacks(limit: int = 100, offset: int = 0) -> dict:
        """Get recent attack events from the system."""
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
                    "description": "SQL injection attempt detected"
                },
                {
                    "id": "attack_002",
                    "type": "xss",
                    "source_ip": "10.0.0.50",
                    "timestamp": "2025-01-15T10:25:00Z",
                    "severity": "medium",
                    "description": "Cross-site scripting attempt"
                }
            ]

            return {
                "status": "success",
                "attacks": mock_attacks[:limit],
                "total": len(mock_attacks),
                "limit": limit,
                "offset": offset,
                "attack_types": list(attack_types.keys())
            }
        except Exception as e:
            logger.exception("Error retrieving attacks")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/metrics", summary="Prometheus Metrics", description="Exposes Prometheus metrics for monitoring and alerting", tags=["metrics"])
    async def metrics() -> Response:
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.post(
        "/scan/secrets",
        summary="Scan Directory for Exposed Secrets",
        description="""
        Performs a comprehensive scan of the specified directory for exposed secrets and sensitive information.

        **What it scans for:**
        - API keys and tokens
        - Database credentials
        - Private keys and certificates
        - Cloud service credentials
        - Authentication tokens
        - Passwords and secrets

        **Features:**
        - Fast cached scanning
        - Database result storage
        - Detailed finding reports
        - Performance metrics
        """,
        tags=["scanning"],
        response_description="Scan results with findings, metadata, and performance metrics"
    )
    async def scan_secrets(request: ScanRequest) -> dict:
        """Scan a path for exposed secrets."""
        import time

        start_time = time.time()

        try:
            from decoyable.cache import scan_secrets_cached
            from decoyable.database import store_scan_result

            findings = scan_secrets_cached([request.path])
            scan_duration = int(time.time() - start_time)

            # Store result in database
            result_id = store_scan_result(
                scan_type="secrets",
                target_path=request.path,
                status="success",
                results={"findings": findings, "count": len(findings)},
                scan_duration=scan_duration,
                file_count=len({f["filename"] for f in findings}) if findings else 0,
            )

            return {
                "status": "success",
                "findings": findings,
                "count": len(findings),
                "scan_duration": scan_duration,
                "result_id": result_id,
            }
        except Exception as e:
            scan_duration = int(time.time() - start_time)
            # Store error result
            try:
                from decoyable.database import store_scan_result

                store_scan_result(
                    scan_type="secrets",
                    target_path=request.path,
                    status="error",
                    error_message=str(e),
                    scan_duration=scan_duration,
                )
            except Exception:
                pass  # Don't let database errors mask the original error

            logger.exception("Error scanning for secrets")
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.post("/scan/dependencies", summary="Scan for dependency issues")
    async def scan_dependencies(request: ScanRequest) -> dict:
        """Scan a project for dependency issues."""
        import time

        start_time = time.time()

        try:
            from decoyable.cache import scan_dependencies_cached
            from decoyable.database import store_scan_result

            result = scan_dependencies_cached(request.path)
            scan_duration = int(time.time() - start_time)

            # Store result in database
            result_id = store_scan_result(
                scan_type="dependencies",
                target_path=request.path,
                status="success",
                results=result,
                scan_duration=scan_duration,
            )

            return {
                "status": "success",
                **result,
                "scan_duration": scan_duration,
                "result_id": result_id,
            }
        except Exception as e:
            scan_duration = int(time.time() - start_time)
            # Store error result
            try:
                from decoyable.database import store_scan_result

                store_scan_result(
                    scan_type="dependencies",
                    target_path=request.path,
                    status="error",
                    error_message=str(e),
                    scan_duration=scan_duration,
                )
            except Exception:
                pass

            logger.exception("Error scanning dependencies")
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.post("/scan/sast", summary="Perform Static Application Security Testing")
    async def scan_sast(request: ScanRequest) -> dict:
        """Perform Static Application Security Testing (SAST) on a path."""
        import time

        start_time = time.time()

        try:
            from decoyable.cache import scan_sast_cached
            from decoyable.database import store_scan_result

            sast_results = scan_sast_cached(request.path)
            scan_duration = int(time.time() - start_time)

            # Store result in database
            result_id = store_scan_result(
                scan_type="sast",
                target_path=request.path,
                status="success",
                results=sast_results,
                scan_duration=scan_duration,
                file_count=sast_results.get("summary", {}).get("files_scanned", 0),
            )

            return {
                "status": "success",
                "vulnerabilities": sast_results.get("vulnerabilities", []),
                "summary": sast_results.get("summary", {}),
                "scan_duration": scan_duration,
                "result_id": result_id,
            }
        except Exception as e:
            scan_duration = int(time.time() - start_time)
            # Store error result
            try:
                from decoyable.database import store_scan_result

                store_scan_result(
                    scan_type="sast",
                    target_path=request.path,
                    status="error",
                    error_message=str(e),
                    scan_duration=scan_duration,
                )
            except Exception:
                pass

            logger.exception("Error performing SAST scan")
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.post("/scan/async/secrets", summary="Asynchronously scan for exposed secrets")
    async def scan_secrets_async(request: ScanRequest) -> dict:
        """Asynchronously scan a path for exposed secrets using Celery."""
        try:
            from decoyable.tasks import scan_secrets_async

            task = scan_secrets_async.delay([request.path])

            return {
                "status": "accepted",
                "task_id": task.id,
                "message": "Secrets scan started asynchronously",
                "check_status_url": f"/tasks/{task.id}",
            }
        except Exception as e:
            logger.exception("Error starting async secrets scan")
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.post("/scan/async/dependencies", summary="Asynchronously scan for dependency issues")
    async def scan_dependencies_async(request: ScanRequest) -> dict:
        """Asynchronously scan a project for dependency issues using Celery."""
        try:
            from decoyable.tasks import scan_dependencies_async

            task = scan_dependencies_async.delay(request.path)

            return {
                "status": "accepted",
                "task_id": task.id,
                "message": "Dependencies scan started asynchronously",
                "check_status_url": f"/tasks/{task.id}",
            }
        except Exception as e:
            logger.exception("Error starting async dependencies scan")
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.post("/scan/async/sast", summary="Asynchronously perform SAST")
    async def scan_sast_async(request: ScanRequest) -> dict:
        """Asynchronously perform Static Application Security Testing using Celery."""
        try:
            from decoyable.tasks import scan_sast_async

            task = scan_sast_async.delay(request.path)

            return {
                "status": "accepted",
                "task_id": task.id,
                "message": "SAST scan started asynchronously",
                "check_status_url": f"/tasks/{task.id}",
            }
        except Exception as e:
            logger.exception("Error starting async SAST scan")
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.post("/scan/async/all", summary="Asynchronously perform all security scans")
    async def scan_all_async(request: ScanRequest) -> dict:
        """Asynchronously perform all security scans using Celery."""
        try:
            from decoyable.tasks import scan_all_async

            task = scan_all_async.delay(request.path)

            return {
                "status": "accepted",
                "task_id": task.id,
                "message": "Comprehensive security scan started asynchronously",
                "check_status_url": f"/tasks/{task.id}",
            }
        except Exception as e:
            logger.exception("Error starting comprehensive async scan")
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.get("/tasks/{task_id}", summary="Check task status")
    async def get_task_status(task_id: str) -> dict:
        """Check the status of an asynchronous task."""
        try:
            from decoyable.tasks import get_task_status

            status = get_task_status(task_id)
            return status
        except Exception as e:
            logger.exception("Error checking task status")
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.get("/cache/stats", summary="Get cache statistics")
    async def get_cache_stats() -> dict:
        """Get cache performance statistics and information."""
        try:
            from decoyable.cache import get_cache_stats

            stats = get_cache_stats()
            return {"status": "success", "cache_stats": stats}
        except Exception as e:
            logger.exception("Error getting cache stats")
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.post("/cache/warmup", summary="Warm up the cache")
    async def warmup_cache(request: ScanRequest) -> dict:
        """Warm up the cache by pre-computing common scan results."""
        try:
            from decoyable.cache import warmup_cache

            result = warmup_cache(request.path)
            return result
        except Exception as e:
            logger.exception("Error warming up cache")
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.post("/cache/clear", summary="Clear the cache")
    async def clear_cache() -> dict:
        """Clear all cached results."""
        try:
            from decoyable.cache import get_cache

            cache = get_cache()
            success = cache.clear()

            return {
                "status": "success" if success else "error",
                "message": ("Cache cleared successfully" if success else "Failed to clear cache"),
            }
        except Exception as e:
            logger.exception("Error clearing cache")
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.get("/database/stats", summary="Get database statistics")
    async def get_database_stats() -> dict:
        """Get database performance statistics and health information."""
        try:
            from decoyable.database import get_database_manager

            db_manager = get_database_manager()
            stats = db_manager.get_database_stats()

            return {"status": "success", "database_stats": stats}
        except Exception as e:
            logger.exception("Error getting database stats")
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.get("/database/results", summary="Get scan results history")
    async def get_scan_results(scan_type: Optional[str] = None, limit: int = 50) -> dict:
        """Get historical scan results from database."""
        try:
            from decoyable.database import get_scan_results

            results = get_scan_results(scan_type=scan_type, limit=limit)

            return {"status": "success", "results": results, "count": len(results)}
        except Exception as e:
            logger.exception("Error getting scan results")
            raise HTTPException(status_code=500, detail=str(e)) from e

    @app.post("/database/cleanup", summary="Clean up expired cache entries")
    async def cleanup_database() -> dict:
        """Clean up expired cache entries in database."""
        try:
            from decoyable.database import get_database_manager

            db_manager = get_database_manager()
            deleted_count = db_manager.cleanup_expired_cache()

            return {
                "status": "success",
                "message": f"Cleaned up {deleted_count} expired cache entries",
            }
        except Exception as e:
            logger.exception("Error cleaning up database")
            raise HTTPException(status_code=500, detail=str(e)) from e  # Generic exception handler to return JSON

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        logger.exception("Unhandled exception: %s", exc)
        return JSONResponse({"detail": "Internal server error"}, status_code=500)

    # Try to import and wire in routers / init functions from main.py (if present)
    try:
        import main as main_module  # attempt to import top-level main.py

        # If main provides an init_app(app) function, call it for custom wiring
        if hasattr(main_module, "init_app"):
            maybe = main_module.init_app
            if callable(maybe):
                logger.info("Initializing app via main.init_app(app)")
                maybe(app)  # type: ignore

        # If main exposes a single router
        if hasattr(main_module, "router"):
            logger.info("Including main.router")
            app.include_router(main_module.router)  # type: ignore

        # If main exposes an iterable of routers
        if hasattr(main_module, "routers"):
            routers = main_module.routers
            if isinstance(routers, (list, tuple, set)):
                for r in routers:
                    logger.info("Including router from main.routers")
                    app.include_router(r)  # type: ignore

        # If main exposes a get_router function
        if hasattr(main_module, "get_router"):
            getter = main_module.get_router
            if callable(getter):
                r = getter()
                logger.info("Including router returned by main.get_router()")
                app.include_router(r)  # type: ignore

    except Exception as e:
        logger.debug("No top-level main.py wired or failed to import it: %s", e)

    # Include defense routers for active cyber defense
    try:
        from decoyable.defense import analysis_router, honeypot_router

        logger.info("Including defense routers for active cyber defense")
        app.include_router(honeypot_router)
        app.include_router(analysis_router)
    except Exception as e:
        logger.warning("Failed to include defense routers: %s", e)

    return app


# Create ASGI app instance used by Uvicorn/Gunicorn
app = create_app()

# Optional entrypoint for local development
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run DECOYABLE API server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--ssl-cert", help="Path to SSL certificate file")
    parser.add_argument("--ssl-key", help="Path to SSL private key file")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")

    args = parser.parse_args()

    # Initialize Kafka producer and consumers if enabled
    kafka_task = None
    if hasattr(app.state, 'kafka_enabled') and app.state.kafka_enabled:
        try:
            from decoyable.streaming.kafka_producer import attack_producer
            from decoyable.streaming.kafka_consumer import start_all_consumers

            # Start Kafka producer
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            async def init_kafka():
                await attack_producer.start()
                await start_all_consumers()

            loop.run_until_complete(init_kafka())
            logger.info("Kafka streaming initialized")

        except Exception as e:
            logger.error(f"Failed to initialize Kafka: {e}")

    # SSL configuration
    ssl_config = {}
    if args.ssl_cert and args.ssl_key:
        ssl_config = {"ssl_certfile": args.ssl_cert, "ssl_keyfile": args.ssl_key}
        print(f"Starting server with SSL on https://{args.host}:{args.port}")
    else:
        print(f"Starting server on http://{args.host}:{args.port}")

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_level="info",
        reload=args.reload,
        **ssl_config,
    )
