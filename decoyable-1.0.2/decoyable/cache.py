"""Redis-based caching layer for DECOYABLE performance optimization."""

import hashlib
import json
import logging
import os
import time
from functools import wraps
from typing import Any, Dict, List, Optional

try:
    import redis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

logger = logging.getLogger(__name__)


class Cache:
    """Redis-based caching with fallback to in-memory cache."""

    def __init__(self, redis_url: Optional[str] = None, default_ttl: int = 3600):
        """
        Initialize cache with Redis backend.

        Args:
            redis_url: Redis connection URL (redis://host:port/db)
            default_ttl: Default time-to-live in seconds
        """
        self.default_ttl = default_ttl
        self.redis_client = None
        self.memory_cache: Dict[str, Dict[str, Any]] = {}

        if REDIS_AVAILABLE and redis_url:
            try:
                self.redis_client = redis.from_url(redis_url)
                # Test connection
                self.redis_client.ping()
                logger.info("Redis cache initialized successfully")
            except Exception as e:
                logger.warning(f"Failed to connect to Redis: {e}. Using memory cache.")
                self.redis_client = None
        else:
            logger.info("Redis not available or not configured. Using memory cache.")

    def _make_key(self, *args, **kwargs) -> str:
        """Create a consistent cache key from arguments."""
        # Sort kwargs for consistent key generation
        sorted_kwargs = sorted(kwargs.items())
        key_data = json.dumps({"args": args, "kwargs": sorted_kwargs}, sort_keys=True)
        return hashlib.sha256(key_data.encode()).hexdigest()

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        if self.redis_client:
            try:
                data = self.redis_client.get(key)
                if data:
                    return json.loads(data.decode("utf-8"))
            except Exception as e:
                logger.warning(f"Redis get error: {e}")
                return None
        else:
            # Memory cache fallback
            cache_entry = self.memory_cache.get(key)
            if cache_entry:
                if time.time() < cache_entry["expires"]:
                    return cache_entry["value"]
                else:
                    # Expired, remove it
                    del self.memory_cache[key]

        return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache with optional TTL."""
        ttl = ttl or self.default_ttl

        if self.redis_client:
            try:
                data = json.dumps(value)
                return bool(self.redis_client.setex(key, ttl, data))
            except Exception as e:
                logger.warning(f"Redis set error: {e}")
                return False
        else:
            # Memory cache fallback
            self.memory_cache[key] = {"value": value, "expires": time.time() + ttl}
            return True

    def delete(self, key: str) -> bool:
        """Delete key from cache."""
        if self.redis_client:
            try:
                return bool(self.redis_client.delete(key))
            except Exception as e:
                logger.warning(f"Redis delete error: {e}")
                return False
        else:
            return bool(self.memory_cache.pop(key, None))

    def clear(self) -> bool:
        """Clear all cache entries."""
        if self.redis_client:
            try:
                return bool(self.redis_client.flushdb())
            except Exception as e:
                logger.warning(f"Redis clear error: {e}")
                return False
        else:
            self.memory_cache.clear()
            return True

    def exists(self, key: str) -> bool:
        """Check if key exists in cache."""
        if self.redis_client:
            try:
                return bool(self.redis_client.exists(key))
            except Exception as e:
                logger.warning(f"Redis exists error: {e}")
                return False
        else:
            cache_entry = self.memory_cache.get(key)
            if cache_entry:
                if time.time() < cache_entry["expires"]:
                    return True
                else:
                    # Expired, remove it
                    del self.memory_cache[key]
            return False


# Global cache instance
_cache_instance: Optional[Cache] = None


def get_cache() -> Cache:
    """Get or create global cache instance."""
    global _cache_instance

    if _cache_instance is None:
        redis_url = os.getenv("REDIS_URL")
        _cache_instance = Cache(redis_url=redis_url)

    return _cache_instance


def cached(ttl: Optional[int] = None, key_prefix: str = ""):
    """
    Decorator to cache function results.

    Args:
        ttl: Time-to-live in seconds (uses cache default if None)
        key_prefix: Prefix for cache keys to avoid collisions
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            cache = get_cache()
            cache_key = f"{key_prefix}:{func.__name__}:{cache._make_key(*args, **kwargs)}"

            # Try to get from cache first
            cached_result = cache.get(cache_key)
            if cached_result is not None:
                logger.debug(f"Cache hit for {func.__name__}")
                return cached_result

            # Cache miss, execute function
            logger.debug(f"Cache miss for {func.__name__}")
            result = func(*args, **kwargs)

            # Cache the result
            cache.set(cache_key, result, ttl)
            return result

        return wrapper

    return decorator


# Cache-enabled scanner functions
@cached(ttl=1800, key_prefix="secrets")  # Cache for 30 minutes
def scan_secrets_cached(paths: List[str]) -> List[Dict[str, Any]]:
    """Cached version of secrets scanning."""
    from decoyable.scanners import secrets

    findings = secrets.scan_paths(paths)
    results = []
    for finding in findings:
        results.append(
            {
                "filename": finding.filename,
                "lineno": finding.lineno,
                "secret_type": finding.secret_type,
                "masked": finding.masked(),
                "context": finding.context,
            }
        )

    return results


@cached(ttl=3600, key_prefix="deps")  # Cache for 1 hour
def scan_dependencies_cached(path: str) -> Dict[str, Any]:
    """Cached version of dependency scanning."""
    from decoyable.scanners import deps

    missing_imports, import_mapping = deps.missing_dependencies(path)

    results = []
    for imp in sorted(missing_imports):
        providers = import_mapping.get(imp, [])
        results.append({"import": imp, "providers": providers})

    return {"missing_dependencies": results, "count": len(results)}


@cached(ttl=1800, key_prefix="sast")  # Cache for 30 minutes
def scan_sast_cached(path: str) -> Dict[str, Any]:
    """Cached version of SAST scanning."""
    from decoyable.scanners import sast

    return sast.scan_sast(path)


def get_cache_stats() -> Dict[str, Any]:
    """Get cache statistics and information."""
    cache = get_cache()

    stats = {
        "cache_type": "redis" if cache.redis_client else "memory",
        "redis_available": REDIS_AVAILABLE,
    }

    if cache.redis_client:
        try:
            info = cache.redis_client.info()
            stats.update(
                {
                    "redis_connected": True,
                    "redis_memory_used": info.get("used_memory_human", "unknown"),
                    "redis_keys_count": cache.redis_client.dbsize(),
                    "redis_uptime_days": info.get("uptime_in_days", 0),
                }
            )
        except Exception as e:
            stats.update({"redis_connected": False, "redis_error": str(e)})
    else:
        stats.update(
            {
                "memory_cache_entries": len(cache.memory_cache),
            }
        )

    return stats


def warmup_cache(target_path: str = ".") -> Dict[str, Any]:
    """
    Warm up the cache by pre-computing common scan results.

    Returns statistics about cache warmup.
    """
    logger.info("Starting cache warmup...")

    start_time = time.time()
    operations = []

    try:
        # Warm up secrets scan
        secrets_result = scan_secrets_cached([target_path])
        operations.append({"operation": "secrets_scan", "cached": True, "items": len(secrets_result)})

        # Warm up dependencies scan
        deps_result = scan_dependencies_cached(target_path)
        operations.append({"operation": "deps_scan", "cached": True, "items": deps_result["count"]})

        # Warm up SAST scan
        sast_result = scan_sast_cached(target_path)
        operations.append(
            {
                "operation": "sast_scan",
                "cached": True,
                "vulnerabilities": sast_result["summary"]["total_vulnerabilities"],
            }
        )

    except Exception as e:
        logger.error(f"Cache warmup failed: {e}")
        return {"status": "error", "error": str(e)}

    duration = time.time() - start_time

    return {
        "status": "success",
        "duration_seconds": round(duration, 2),
        "operations": operations,
        "cache_stats": get_cache_stats(),
    }
