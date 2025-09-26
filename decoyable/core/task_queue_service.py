"""
Task Queue Service Module

Provides Celery-based asynchronous task processing with service registry integration.
Handles background scanning tasks, job queuing, and result management.
"""

import asyncio
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Optional Celery import
try:
    from celery import Celery
    from celery.result import AsyncResult, GroupResult

    CELERY_AVAILABLE = True
except ImportError:
    CELERY_AVAILABLE = False
    Celery = None
    AsyncResult = None
    GroupResult = None

from decoyable.core.registry import ServiceRegistry

logger = logging.getLogger(__name__)


class TaskQueueService:
    """
    Celery-based task queue service with dependency injection.

    Provides asynchronous task processing for security scans and background operations.
    Integrates with the service registry for clean dependency management.
    """

    def __init__(self, registry: ServiceRegistry):
        """
        Initialize task queue service with service registry.

        Args:
            registry: Service registry for dependency injection
        """
        self.registry = registry
        self.celery_app = None
        self.scanner_service = None
        self.database_service = None
        self.cache_service = None
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the task queue service asynchronously."""
        if self._initialized:
            return

        if not CELERY_AVAILABLE:
            logger.warning("Celery not available. Task queue functionality disabled.")
            self._initialized = True
            return

        try:
            # Validate required environment variables
            broker_url = os.getenv("CELERY_BROKER_URL")
            result_backend = os.getenv("CELERY_RESULT_BACKEND")
            
            if not broker_url:
                raise ValueError("CELERY_BROKER_URL environment variable must be set")
            if not result_backend:
                raise ValueError("CELERY_RESULT_BACKEND environment variable must be set")

            # Initialize Celery app
            self.celery_app = Celery(
                "decoyable",
                broker=broker_url,
                backend=result_backend,
                include=["decoyable.core.task_definitions"],
            )

            # Configure Celery
            self.celery_app.conf.update(
                task_serializer="json",
                accept_content=["json"],
                result_serializer="json",
                timezone="UTC",
                enable_utc=True,
                task_routes={
                    "decoyable.tasks.scan_secrets_async": {"queue": "security"},
                    "decoyable.tasks.scan_dependencies_async": {"queue": "security"},
                    "decoyable.tasks.scan_sast_async": {"queue": "security"},
                    "decoyable.tasks.scan_all_async": {"queue": "security"},
                },
                task_default_queue="security",
                task_default_exchange="security",
task_default_routing_key = os.getenv("task_default_routing_key", "")
                # Performance tuning
                worker_prefetch_multiplier=1,
                task_acks_late=True,
                worker_max_tasks_per_child=50,
            )

            # Get service dependencies
            self.scanner_service = await self.registry.get_service_async("scanner_service")
            self.database_service = await self.registry.get_service_async("database_service")
            self.cache_service = await self.registry.get_service_async("cache_service")

            self._initialized = True
            logger.info("Task queue service initialized successfully")

        except Exception as e:
            logger.warning(f"Failed to initialize task queue service: {e}. Task queue disabled.")
            self._initialized = True

    async def submit_scan_task(self, scan_type: str, target_path: Union[str, Path], **kwargs) -> str:
        """
        Submit a security scan task to the queue.

        Args:
            scan_type: Type of scan ("secrets", "dependencies", "sast", "all")
            target_path: Path to scan
            **kwargs: Additional scan parameters

        Returns:
            Task ID for tracking
        """
        await self.initialize()

        if not CELERY_AVAILABLE or not self.celery_app:
            raise RuntimeError("Task queue service not available - Celery not installed")

        target_path = str(target_path)

        if scan_type == "secrets":
            task = self.celery_app.send_task("decoyable.tasks.scan_secrets_async", args=[[target_path]], kwargs=kwargs)
        elif scan_type == "dependencies":
            task = self.celery_app.send_task(
                "decoyable.tasks.scan_dependencies_async", args=[target_path], kwargs=kwargs
            )
        elif scan_type == "sast":
            task = self.celery_app.send_task("decoyable.tasks.scan_sast_async", args=[target_path], kwargs=kwargs)
        elif scan_type == "all":
            task = self.celery_app.send_task("decoyable.tasks.scan_all_async", args=[target_path], kwargs=kwargs)
        else:
            raise ValueError(f"Unknown scan type: {scan_type}")

        logger.info(f"Submitted {scan_type} scan task for {target_path}, task_id: {task.id}")
        return task.id

    async def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """
        Get the status of a task.

        Args:
            task_id: Task ID to check

        Returns:
            Task status information
        """
        await self.initialize()

        if not CELERY_AVAILABLE or not self.celery_app:
            return {"state": "ERROR", "error": "Task queue service not available - Celery not installed"}

        try:
            result = AsyncResult(task_id, app=self.celery_app)

            if result.state == "PENDING":
                return {
                    "task_id": task_id,
                    "state": result.state,
                    "message": "Task is pending...",
                    "progress": {"current": 0, "total": 1},
                }
            elif result.state == "PROGRESS":
                return {
                    "task_id": task_id,
                    "state": result.state,
                    "message": result.info.get("message", "Task in progress..."),
                    "progress": {"current": result.info.get("current", 0), "total": result.info.get("total", 1)},
                }
            elif result.state == "SUCCESS":
                return {
                    "task_id": task_id,
                    "state": result.state,
                    "result": result.result,
                    "completed_at": result.date_done.isoformat() if result.date_done else None,
                }
            else:  # FAILURE, RETRY, etc.
                return {
                    "task_id": task_id,
                    "state": result.state,
                    "error": str(result.info) if result.info else "Unknown error",
                    "traceback": result.traceback if hasattr(result, "traceback") else None,
                }

        except Exception as e:
            logger.error(f"Error getting task status for {task_id}: {e}")
            return {"task_id": task_id, "state": "ERROR", "error": str(e)}

    async def get_queue_stats(self) -> Dict[str, Any]:
        """
        Get task queue statistics and health information.

        Returns:
            Queue statistics
        """
        await self.initialize()

        stats = {
            "service_available": CELERY_AVAILABLE and self.celery_app is not None,
            "celery_installed": CELERY_AVAILABLE,
            "broker_url": os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0"),
            "result_backend": os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0"),
        }

        if not CELERY_AVAILABLE or not self.celery_app:
            stats["error"] = "Task queue not available"
            return stats

        try:
            # Get active queues (this is a simplified version)
            inspect = self.celery_app.control.inspect()

            active_tasks = inspect.active()
            stats.update(
                {
                    "active_tasks": active_tasks or {},
                    "worker_count": len(active_tasks) if active_tasks else 0,
                }
            )

            # Get queue lengths (requires Redis broker)
            try:
                from redis import Redis

                redis_client = Redis.from_url(stats["broker_url"])
                queue_length = redis_client.llen("security")
                stats["queue_length"] = queue_length
            except Exception:
                stats["queue_length"] = "unknown"

        except Exception as e:
            stats["error"] = str(e)

        return stats