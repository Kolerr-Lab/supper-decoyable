"""
Cache Service Module

Provides unified caching functionality with Redis/memory fallback and database persistence.
Integrates with the service registry for dependency injection.
"""

import asyncio
import hashlib
import json
import logging
import time
from typing import Any, Dict, List, Optional, Union
from functools import wraps

from decoyable.core.registry import ServiceRegistry
from decoyable.cache import Cache

logger = logging.getLogger(__name__)


class CacheService:
    """
    Unified caching service combining Redis/memory cache with database persistence.

    Provides high-performance caching with fallback mechanisms and persistent
    storage for scan results.
    """

    def __init__(self, registry: ServiceRegistry):
        """
        Initialize cache service with service registry.

        Args:
            registry: Service registry for dependency injection
        """
        self.registry = registry
        self.cache = Cache()  # Redis/memory cache instance
        self.database_service = None
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the cache service asynchronously."""
        if self._initialized:
            return

        try:
            # Get database service from registry
            self.database_service = await self.registry.get_service_async("database_service")
            self._initialized = True
            logger.info("Cache service initialized successfully")
        except Exception as e:
            logger.warning(f"Failed to initialize database service for cache: {e}. Using cache-only mode.")
            self.database_service = None
            self._initialized = True

    def _make_cache_key(self, *args, **kwargs) -> str:
        """
        Create a consistent cache key from arguments.

        Args:
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            str: Consistent cache key
        """
        # Convert args to strings and sort kwargs
        key_parts = [str(arg) for arg in args]
        key_parts.extend(f"{k}:{v}" for k, v in sorted(kwargs.items()))

        # Create hash for consistent key length
        key_string = "|".join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()

    async def get(self, key: str) -> Any:
        """
        Get value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found
        """
        await self.initialize()

        # Try Redis/memory cache first
        value = self.cache.get(key)
        if value is not None:
            logger.debug(f"Cache hit for key: {key}")
            return value

        # Try database cache if available
        if self.database_service:
            try:
                db_cache = await self.database_service.get_scan_cache(key)
                if db_cache:
                    # Store in fast cache for future requests
                    self.cache.set(key, db_cache["results"], ttl=300)  # 5 minute TTL in fast cache
                    logger.debug(f"Database cache hit for key: {key}")
                    return db_cache["results"]
            except Exception as e:
                logger.warning(f"Database cache lookup failed: {e}")

        logger.debug(f"Cache miss for key: {key}")
        return None

    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        scan_type: Optional[str] = None,
        target_path: Optional[str] = None,
        persist: bool = False
    ) -> None:
        """
        Set value in cache.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds (uses cache default if None)
            scan_type: Type of scan for database persistence
            target_path: Target path for database persistence
            persist: Whether to persist to database
        """
        await self.initialize()

        # Always set in fast cache
        self.cache.set(key, value, ttl)

        # Persist to database if requested and available
        if persist and self.database_service and scan_type and target_path:
            try:
                await self.database_service.set_scan_cache(
                    cache_key=key,
                    scan_type=scan_type,
                    target_path=target_path,
                    results=value,
                    ttl_seconds=ttl or 3600
                )
                logger.debug(f"Persisted cache entry to database: {key}")
            except Exception as e:
                logger.warning(f"Database cache persistence failed: {e}")

    async def delete(self, key: str) -> bool:
        """
        Delete key from cache.

        Args:
            key: Cache key to delete

        Returns:
            bool: True if key was deleted
        """
        await self.initialize()

        # Delete from fast cache
        deleted = self.cache.delete(key)

        # Delete from database cache if available
        if self.database_service:
            try:
                # Note: Database service doesn't have a delete method yet
                # This would need to be added to DatabaseService
                pass
            except Exception as e:
                logger.warning(f"Database cache deletion failed: {e}")

        return deleted

    def cached(
        self,
        ttl: Optional[int] = None,
        key_prefix: str = "",
        scan_type: Optional[str] = None,
        persist: bool = False
    ):
        """
        Decorator to cache async function results.

        Args:
            ttl: Time-to-live in seconds (uses cache default if None)
            key_prefix: Prefix for cache keys to avoid collisions
            scan_type: Type of scan for database persistence
            persist: Whether to persist results to database
        """

        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Create cache key
                cache_key = f"{key_prefix}:{func.__name__}:{self._make_cache_key(*args, **kwargs)}"

                # Try to get from cache first
                cached_result = await self.get(cache_key)
                if cached_result is not None:
                    logger.debug(f"Cache hit for {func.__name__}")
                    return cached_result

                # Cache miss, execute function
                logger.debug(f"Cache miss for {func.__name__}")
                result = await func(*args, **kwargs)

                # Extract target path for persistence if it's a scan function
                target_path = None
                if args and len(args) > 1:
                    # Assume first arg after self is the path
                    target_path = str(args[1]) if len(args) > 1 else str(args[0]) if args else None

                # Cache the result
                await self.set(
                    cache_key,
                    result,
                    ttl,
                    scan_type=scan_type,
                    target_path=target_path,
                    persist=persist
                )
                return result

            return wrapper

        return decorator

    async def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive cache statistics.

        Returns:
            Dict containing cache statistics
        """
        await self.initialize()

        stats = {
            "cache_type": "redis" if self.cache.redis_client else "memory",
            "redis_available": self.cache.redis_available,
            "database_cache_available": self.database_service is not None,
        }

        # Fast cache stats
        if self.cache.redis_client:
            try:
                info = self.cache.redis_client.info()
                stats.update({
                    "redis_connected": True,
                    "redis_memory_used": info.get("used_memory_human", "unknown"),
                    "redis_keys_count": self.cache.redis_client.dbsize(),
                    "redis_uptime_days": info.get("uptime_in_days", 0),
                })
            except Exception as e:
                stats.update({"redis_connected": False, "redis_error": str(e)})
        else:
            stats.update({
                "memory_cache_entries": len(self.cache.memory_cache),
            })

        # Database cache stats
        if self.database_service:
            try:
                # This would need a method in DatabaseService to get cache stats
                # For now, just indicate availability
                stats["database_cache_enabled"] = True
            except Exception as e:
                stats["database_cache_error"] = str(e)

        return stats

    async def warmup_cache(self, target_path: str = ".") -> Dict[str, Any]:
        """
        Warm up the cache by pre-computing common scan results.

        Args:
            target_path: Path to scan for warmup

        Returns:
            Dict with warmup statistics
        """
        await self.initialize()

        logger.info("Starting cache warmup...")
        start_time = time.time()

        operations = []

        try:
            # Get scanner service
            scanner_service = await self.registry.get_service_async("scanner_service")

            # Warm up secrets scan
            secrets_result = await scanner_service.scan_secrets([target_path])
            operations.append({
                "operation": "secrets_scan",
                "cached": True,
                "items": len(secrets_result)
            })

            # Warm up dependencies scan
            deps_result = await scanner_service.scan_dependencies(target_path)
            operations.append({
                "operation": "deps_scan",
                "cached": True,
                "items": deps_result.get("count", 0)
            })

            # Warm up SAST scan
            sast_result = await scanner_service.scan_sast(target_path)
            operations.append({
                "operation": "sast_scan",
                "cached": True,
                "vulnerabilities": sast_result.get("summary", {}).get("total_vulnerabilities", 0)
            })

        except Exception as e:
            logger.error(f"Cache warmup failed: {e}")
            return {"status": "error", "error": str(e)}

        duration = time.time() - start_time

        return {
            "status": "success",
            "duration_seconds": round(duration, 2),
            "operations": operations,
            "cache_stats": await self.get_cache_stats(),
        }

    async def cleanup_expired_cache(self) -> Dict[str, Any]:
        """
        Clean up expired cache entries from all cache layers.

        Returns:
            Dict with cleanup statistics
        """
        await self.initialize()

        stats = {"fast_cache_cleaned": 0, "database_cache_cleaned": 0}

        # Clean fast cache (memory cleanup is automatic)
        if self.cache.redis_client:
            try:
                # Redis handles TTL automatically, but we can get stats
                pass
            except Exception as e:
                logger.warning(f"Fast cache cleanup failed: {e}")

        # Clean database cache
        if self.database_service:
            try:
                deleted_count = await self.database_service.cleanup_expired_cache()
                stats["database_cache_cleaned"] = deleted_count
            except Exception as e:
                logger.warning(f"Database cache cleanup failed: {e}")

        return stats