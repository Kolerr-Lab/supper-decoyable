"""
Celery Task Definitions for DECOYABLE

Service-integrated Celery tasks that use dependency injection and the service registry.
These tasks replace the old global task definitions with proper service architecture.
"""

import logging
from typing import Any, Dict, List

from decoyable.core.task_queue_service import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="decoyable.tasks.scan_secrets_async")
def scan_secrets_async(self, paths: List[str]) -> Dict[str, Any]:
    """Asynchronous task to scan for exposed secrets using service architecture."""
    try:
        # Import here to avoid circular imports
        import asyncio
        from decoyable.core.registry import get_service_registry

        async def _scan():
            registry = get_service_registry()
            scanner_service = await registry.get_service_async("scanner_service")

            self.update_state(state="PROGRESS", meta={"message": "Scanning for secrets..."})

            # Use the scanner service
            report = await scanner_service.scan_secrets(paths)

            return {
                "status": "success",
                "findings": report.results,
                "count": len(report.results),
                "paths_scanned": paths,
                "scan_time_ms": report.summary.scan_time_ms,
            }

        # Run async function in sync context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(_scan())
        finally:
            loop.close()

    except Exception as e:
        logger.exception("Error in async secrets scan")
        self.update_state(state="FAILURE", meta={"error": str(e)})
        raise


@celery_app.task(bind=True, name="decoyable.tasks.scan_dependencies_async")
def scan_dependencies_async(self, path: str) -> Dict[str, Any]:
    """Asynchronous task to scan for dependency issues using service architecture."""
    try:
        import asyncio
        from decoyable.core.registry import get_service_registry

        async def _scan():
            registry = get_service_registry()
            scanner_service = await registry.get_service_async("scanner_service")

            self.update_state(state="PROGRESS", meta={"message": "Scanning dependencies..."})

            # Use the scanner service
            report = await scanner_service.scan_dependencies(path)

            return {
                "status": "success",
                "missing_dependencies": report.results,
                "count": len(report.results),
                "path_scanned": path,
                "scan_time_ms": report.summary.scan_time_ms,
            }

        # Run async function in sync context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(_scan())
        finally:
            loop.close()

    except Exception as e:
        logger.exception("Error in async dependencies scan")
        self.update_state(state="FAILURE", meta={"error": str(e)})
        raise


@celery_app.task(bind=True, name="decoyable.tasks.scan_sast_async")
def scan_sast_async(self, path: str) -> Dict[str, Any]:
    """Asynchronous task to perform SAST scanning using service architecture."""
    try:
        import asyncio
        from decoyable.core.registry import get_service_registry

        async def _scan():
            registry = get_service_registry()
            scanner_service = await registry.get_service_async("scanner_service")

            self.update_state(state="PROGRESS", meta={"message": "Performing SAST analysis..."})

            # Use the scanner service
            report = await scanner_service.scan_sast(path)

            return {
                "status": "success",
                "vulnerabilities": report.results,
                "summary": report.summary.metadata or {},
                "path_scanned": path,
                "scan_time_ms": report.summary.scan_time_ms,
            }

        # Run async function in sync context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(_scan())
        finally:
            loop.close()

    except Exception as e:
        logger.exception("Error in async SAST scan")
        self.update_state(state="FAILURE", meta={"error": str(e)})
        raise


@celery_app.task(bind=True, name="decoyable.tasks.scan_all_async")
def scan_all_async(self, path: str) -> Dict[str, Any]:
    """Asynchronous task to perform all security scans using service architecture."""
    try:
        import asyncio
        from decoyable.core.registry import get_service_registry

        async def _scan():
            registry = get_service_registry()
            scanner_service = await registry.get_service_async("scanner_service")

            self.update_state(
                state="PROGRESS",
                meta={"message": "Starting comprehensive security scan..."},
            )

            # Use the scanner service to run all scans
            results = await scanner_service.scan_all(path)

            # Format results
            combined_result = {
                "status": "success",
                "secrets": {
                    "findings": results.get("SECRETS", {}).results,
                    "count": len(results.get("SECRETS", {}).results),
                } if "SECRETS" in results else {},
                "dependencies": {
                    "missing_dependencies": results.get("DEPENDENCIES", {}).results,
                    "count": len(results.get("DEPENDENCIES", {}).results),
                } if "DEPENDENCIES" in results else {},
                "sast": {
                    "vulnerabilities": results.get("SAST", {}).results,
                    "summary": results.get("SAST", {}).summary.metadata or {},
                } if "SAST" in results else {},
                "path_scanned": path,
                "scan_timestamp": self.request.id,
            }

            return combined_result

        # Run async function in sync context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(_scan())
        finally:
            loop.close()

    except Exception as e:
        logger.exception("Error in comprehensive async scan")
        self.update_state(state="FAILURE", meta={"error": str(e)})
        raise


@celery_app.task(bind=True, name="decoyable.tasks.process_scan_results_async")
def process_scan_results_async(self, scan_results: Dict[str, Any], scan_type: str) -> Dict[str, Any]:
    """Asynchronous task to process and store scan results."""
    try:
        import asyncio
        from decoyable.core.registry import get_service_registry

        async def _process():
            registry = get_service_registry()
            database_service = await registry.get_service_async("database_service")
            cache_service = await registry.get_service_async("cache_service")

            self.update_state(state="PROGRESS", meta={"message": "Processing scan results..."})

            # Store results in database
            if database_service:
                await database_service.store_scan_results(
                    scan_type=scan_type,
                    results=scan_results,
                    metadata={"processed_by": "task_queue", "task_id": self.request.id}
                )

            # Update cache if available
            if cache_service:
                cache_key = f"scan_results:{scan_type}:{scan_results.get('path_scanned', 'unknown')}"
                await cache_service.set(
                    key=cache_key,
                    value=scan_results,
                    ttl=3600,  # 1 hour
                    scan_type=scan_type,
                    target_path=scan_results.get('path_scanned'),
                    persist=True
                )

            return {
                "status": "success",
                "processed_results": scan_results,
                "scan_type": scan_type,
                "stored_in_db": database_service is not None,
                "cached": cache_service is not None,
            }

        # Run async function in sync context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(_process())
        finally:
            loop.close()

    except Exception as e:
        logger.exception("Error processing scan results")
        self.update_state(state="FAILURE", meta={"error": str(e)})
        raise