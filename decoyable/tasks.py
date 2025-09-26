"""Celery tasks for asynchronous processing in DECOYABLE."""

import logging
import os
from typing import Any, Dict, List

from celery import Celery

# Configure Celery
broker_url = os.getenv("CELERY_BROKER_URL")
result_backend = os.getenv("CELERY_RESULT_BACKEND")

if not broker_url:
    raise ValueError("CELERY_BROKER_URL environment variable must be set")
if not result_backend:
    raise ValueError("CELERY_RESULT_BACKEND environment variable must be set")

celery_app = Celery(
    "decoyable",
    broker=broker_url,
    backend=result_backend,
    include=["decoyable.tasks"],
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_routes={
        "decoyable.tasks.scan_secrets_async": {"queue": "security"},
        "decoyable.tasks.scan_dependencies_async": {"queue": "security"},
        "decoyable.tasks.scan_sast_async": {"queue": "security"},
    },
    task_default_queue="security",
    task_default_exchange="security",
task_default_routing_key = os.getenv("task_default_routing_key", "")
)

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="decoyable.tasks.scan_secrets_async")
def scan_secrets_async(self, paths: List[str]) -> Dict[str, Any]:
    """Asynchronous task to scan for exposed secrets."""
    try:
        from decoyable.scanners import secrets

        self.update_state(state="PROGRESS", meta={"message": "Scanning for secrets..."})

        all_findings = []
        for path in paths:
            findings = secrets.scan_paths([path])
            all_findings.extend(findings)

        results = []
        for finding in all_findings:
            results.append(
                {
                    "filename": finding.filename,
                    "lineno": finding.lineno,
                    "secret_type": finding.secret_type,
                    "masked": finding.masked(),
                    "context": finding.context,
                }
            )

        return {
            "status": "success",
            "findings": results,
            "count": len(results),
            "paths_scanned": paths,
        }

    except Exception as e:
        logger.exception("Error in async secrets scan")
        self.update_state(state="FAILURE", meta={"error": str(e)})
        raise


@celery_app.task(bind=True, name="decoyable.tasks.scan_dependencies_async")
def scan_dependencies_async(self, path: str) -> Dict[str, Any]:
    """Asynchronous task to scan for dependency issues."""
    try:
        from decoyable.scanners import deps

        self.update_state(state="PROGRESS", meta={"message": "Scanning dependencies..."})

        missing_imports, import_mapping = deps.missing_dependencies(path)

        results = []
        for imp in sorted(missing_imports):
            providers = import_mapping.get(imp, [])
            results.append({"import": imp, "providers": providers})

        return {
            "status": "success",
            "missing_dependencies": results,
            "count": len(results),
            "path_scanned": path,
        }

    except Exception as e:
        logger.exception("Error in async dependencies scan")
        self.update_state(state="FAILURE", meta={"error": str(e)})
        raise


@celery_app.task(bind=True, name="decoyable.tasks.scan_sast_async")
def scan_sast_async(self, path: str) -> Dict[str, Any]:
    """Asynchronous task to perform SAST scanning."""
    try:
        from decoyable.scanners import sast

        self.update_state(state="PROGRESS", meta={"message": "Performing SAST analysis..."})

        sast_results = sast.scan_sast(path)

        return {
            "status": "success",
            "vulnerabilities": sast_results.get("vulnerabilities", []),
            "summary": sast_results.get("summary", {}),
            "path_scanned": path,
        }

    except Exception as e:
        logger.exception("Error in async SAST scan")
        self.update_state(state="FAILURE", meta={"error": str(e)})
        raise


@celery_app.task(bind=True, name="decoyable.tasks.scan_all_async")
def scan_all_async(self, path: str) -> Dict[str, Any]:
    """Asynchronous task to perform all security scans."""
    try:
        self.update_state(
            state="PROGRESS",
            meta={"message": "Starting comprehensive security scan..."},
        )

        # Run all scans in parallel using Celery's group/chord
        from celery import group

        # Create group of tasks
        scan_group = group(
            [
                scan_secrets_async.s([path]),
                scan_dependencies_async.s(path),
                scan_sast_async.s(path),
            ]
        )

        # Execute group and wait for results
        group_result = scan_group.apply_async()

        # Collect results
        results = group_result.get(timeout=300)  # 5 minute timeout

        # Combine results
        combined_result = {
            "status": "success",
            "secrets": results[0] if len(results) > 0 else {},
            "dependencies": results[1] if len(results) > 1 else {},
            "sast": results[2] if len(results) > 2 else {},
            "path_scanned": path,
            "scan_timestamp": self.request.id,
        }

        return combined_result

    except Exception as e:
        logger.exception("Error in comprehensive async scan")
        self.update_state(state="FAILURE", meta={"error": str(e)})
        raise


def get_task_status(task_id: str) -> Dict[str, Any]:
    """Get the status of a Celery task."""
    from celery.result import AsyncResult

    result = AsyncResult(task_id, app=celery_app)

    if result.state == "PENDING":
        response = {
            "state": result.state,
            "message": "Task is pending...",
            "current": 0,
            "total": 1,
        }
    elif result.state == "PROGRESS":
        response = {
            "state": result.state,
            "message": result.info.get("message", "Task in progress..."),
            "current": result.info.get("current", 0),
            "total": result.info.get("total", 1),
        }
    elif result.state == "SUCCESS":
        response = {
            "state": result.state,
            "result": result.result,
        }
    else:
        response = {
            "state": result.state,
            "error": str(result.info),
        }

    return response