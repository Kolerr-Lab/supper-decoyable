"""
Database Service Layer

Refactored database service with dependency injection, async operations,
and connection pooling for enterprise-grade performance.
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import JSON, Column, DateTime, Integer, String, Text, create_engine, pool
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.future import select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func

from decoyable.core.config import Settings
from decoyable.core.logging import LoggingService, get_logger
from decoyable.core.registry import ServiceRegistry


# SQLAlchemy Base for models
Base = declarative_base()


# Database models for scan results storage
class ScanResult(Base):
    """Model for storing scan results."""

    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_type = Column(String(50), nullable=False, index=True)  # secrets, deps, sast
    target_path = Column(String(4096), nullable=False)
    status = Column(String(20), nullable=False)  # success, error, in_progress
    results = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    scan_duration = Column(Integer, nullable=True)  # in seconds
    file_count = Column(Integer, nullable=True)


class ScanCache(Base):
    """Model for caching scan results."""

    __tablename__ = "scan_cache"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cache_key = Column(String(128), nullable=False, unique=True, index=True)
    scan_type = Column(String(50), nullable=False, index=True)
    target_path = Column(String(4096), nullable=False)
    results = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    hit_count = Column(Integer, default=0)


class DatabaseService:
    """Database service with async operations and connection pooling."""

    def __init__(
        self,
        config: Settings,
        registry: ServiceRegistry,
        logging_service: LoggingService
    ):
        self.config = config
        self.registry = registry
        self.logging_service = logging_service
        self.logger = get_logger("database.service")

        # Async engine for high-performance operations
        self.async_engine = None
        self.AsyncSessionLocal = None

        # Sync engine for legacy compatibility
        self.sync_engine = None
        self.SessionLocal = None

        self._initialized = False

    async def initialize(self) -> None:
        """Initialize database connections and create tables asynchronously."""
        if self._initialized:
            return

        try:
            database_url = self.config.database.url

            # Convert sync URL to async URL for SQLAlchemy 1.4+
            if database_url.startswith("postgresql"):
                async_url = database_url.replace("postgresql://", "postgresql+asyncpg://")
            elif database_url.startswith("mysql"):
                async_url = database_url.replace("mysql://", "mysql+aiomysql://")
            elif database_url.startswith("sqlite"):
                async_url = database_url.replace("sqlite://", "sqlite+aiosqlite://")
            else:
                async_url = database_url

            # Configure async engine with connection pooling
            if async_url.startswith("postgresql+asyncpg"):
                self.async_engine = create_async_engine(
                    async_url,
                    pool_size=self.config.database.pool_size,
                    max_overflow=self.config.database.max_overflow,
                    pool_timeout=self.config.database.pool_timeout,
                    pool_recycle=3600,  # Recycle connections after 1 hour
                    pool_pre_ping=True,  # Test connections before use
                    echo=self.config.database.echo,
                )
            elif async_url.startswith("mysql+aiomysql"):
                self.async_engine = create_async_engine(
                    async_url,
                    pool_size=self.config.database.pool_size,
                    max_overflow=self.config.database.max_overflow,
                    pool_timeout=self.config.database.pool_timeout,
                    pool_recycle=3600,
                    pool_pre_ping=True,
                    echo=self.config.database.echo,
                )
            else:
                # SQLite async support
                self.async_engine = create_async_engine(
                    async_url,
                    poolclass=pool.NullPool,  # No pooling for SQLite
                    echo=self.config.database.echo,
                )

            # Create async session factory
            self.AsyncSessionLocal = sessionmaker(
                self.async_engine,
                class_=AsyncSession,
                expire_on_commit=False
            )

            # Also create sync engine for backward compatibility
            self.sync_engine = create_engine(
                database_url,
                poolclass=pool.QueuePool,
                pool_size=self.config.database.pool_size,
                max_overflow=self.config.database.max_overflow,
                pool_timeout=self.config.database.pool_timeout,
                pool_recycle=3600,
                pool_pre_ping=True,
                echo=self.config.database.echo,
            )

            self.SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=self.sync_engine
            )

            # Create tables asynchronously
            async with self.async_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            self._initialized = True
            self.logger.info("Database service initialized successfully")

        except Exception as e:
            self.logger.error(f"Failed to initialize database service: {e}")
            raise

    async def shutdown(self) -> None:
        """Shutdown database connections gracefully."""
        if self.async_engine:
            await self.async_engine.dispose()
        if self.sync_engine:
            self.sync_engine.dispose()
        self.logger.info("Database service shutdown complete")

    @asynccontextmanager
    async def get_async_session(self):
        """Get async database session with automatic cleanup."""
        if not self._initialized:
            await self.initialize()

        session = self.AsyncSessionLocal()
        try:
            yield session
        except Exception as e:
            await session.rollback()
            self.logger.error(f"Database session error: {e}")
            raise
        finally:
            await session.close()

    def get_sync_session(self):
        """Get sync database session for legacy compatibility."""
        from contextlib import contextmanager

        if not self._initialized:
            # For sync operations, we need to initialize synchronously
            asyncio.create_task(self.initialize())

        @contextmanager
        def _session_manager():
            session = self.SessionLocal()
            try:
                yield session
            except Exception as e:
                session.rollback()
                self.logger.error(f"Database session error: {e}")
                raise
            finally:
                session.close()

        return _session_manager()

    async def store_scan_result_async(
        self,
        scan_type: str,
        target_path: str,
        status: str,
        results: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None,
        scan_duration: Optional[int] = None,
        file_count: Optional[int] = None,
    ) -> int:
        """Store scan result asynchronously."""
        async with self.get_async_session() as session:
            scan_result = ScanResult(
                scan_type=scan_type,
                target_path=target_path,
                status=status,
                results=results,
                error_message=error_message,
                scan_duration=scan_duration,
                file_count=file_count,
            )
            session.add(scan_result)
            await session.commit()
            await session.refresh(scan_result)
            return scan_result.id

    def store_scan_result_sync(
        self,
        scan_type: str,
        target_path: str,
        status: str,
        results: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None,
        scan_duration: Optional[int] = None,
        file_count: Optional[int] = None,
    ) -> int:
        """Store scan result synchronously for backward compatibility."""
        with self.get_sync_session() as session:
            scan_result = ScanResult(
                scan_type=scan_type,
                target_path=target_path,
                status=status,
                results=results,
                error_message=error_message,
                scan_duration=scan_duration,
                file_count=file_count,
            )
            session.add(scan_result)
            session.commit()
            session.refresh(scan_result)
            return scan_result.id

    async def get_scan_results_async(
        self, scan_type: Optional[str] = None, limit: int = 50, offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Retrieve scan results asynchronously."""
        async with self.get_async_session() as session:
            stmt = select(ScanResult).order_by(ScanResult.created_at.desc())

            if scan_type:
                stmt = stmt.where(ScanResult.scan_type == scan_type)

            stmt = stmt.limit(limit).offset(offset)
            result = await session.execute(stmt)

            results = []
            for scan_result in result.scalars():
                results.append(
                    {
                        "id": scan_result.id,
                        "scan_type": scan_result.scan_type,
                        "target_path": scan_result.target_path,
                        "status": scan_result.status,
                        "results": scan_result.results,
                        "error_message": scan_result.error_message,
                        "created_at": scan_result.created_at.isoformat() if scan_result.created_at else None,
                        "scan_duration": scan_result.scan_duration,
                        "file_count": scan_result.file_count,
                    }
                )

            return results

    def get_scan_results_sync(
        self, scan_type: Optional[str] = None, limit: int = 50, offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Retrieve scan results synchronously."""
        with self.get_sync_session() as session:
            query = session.query(ScanResult).order_by(ScanResult.created_at.desc())

            if scan_type:
                query = query.filter(ScanResult.scan_type == scan_type)

            query = query.limit(limit).offset(offset)

            results = []
            for scan_result in query.all():
                results.append(
                    {
                        "id": scan_result.id,
                        "scan_type": scan_result.scan_type,
                        "target_path": scan_result.target_path,
                        "status": scan_result.status,
                        "results": scan_result.results,
                        "error_message": scan_result.error_message,
                        "created_at": scan_result.created_at.isoformat() if scan_result.created_at else None,
                        "scan_duration": scan_result.scan_duration,
                        "file_count": scan_result.file_count,
                    }
                )

            return results

    async def get_scan_cache_async(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached scan result asynchronously."""
        async with self.get_async_session() as session:
            stmt = select(ScanCache).where(
                ScanCache.cache_key == cache_key,
                ScanCache.expires_at > func.now()
            )
            result = await session.execute(stmt)
            cache_entry = result.scalar_one_or_none()

            if cache_entry:
                # Update hit count
                cache_entry.hit_count += 1
                await session.commit()

                return {
                    "scan_type": cache_entry.scan_type,
                    "target_path": cache_entry.target_path,
                    "results": cache_entry.results,
                    "created_at": cache_entry.created_at.isoformat() if cache_entry.created_at else None,
                    "hit_count": cache_entry.hit_count,
                }

        return None

    async def set_scan_cache_async(
        self,
        cache_key: str,
        scan_type: str,
        target_path: str,
        results: Dict[str, Any],
        ttl_seconds: int = 3600,
    ) -> None:
        """Set cached scan result asynchronously."""
        expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)

        async with self.get_async_session() as session:
            # Check if cache entry already exists
            stmt = select(ScanCache).where(ScanCache.cache_key == cache_key)
            result = await session.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing:
                # Update existing entry
                existing.results = results
                existing.expires_at = expires_at
                existing.hit_count = 0
            else:
                # Create new entry
                cache_entry = ScanCache(
                    cache_key=cache_key,
                    scan_type=scan_type,
                    target_path=target_path,
                    results=results,
                    expires_at=expires_at,
                )
                session.add(cache_entry)

            await session.commit()

    async def cleanup_expired_cache_async(self) -> int:
        """Clean up expired cache entries asynchronously. Returns number of deleted entries."""
        async with self.get_async_session() as session:
            stmt = select(ScanCache).where(ScanCache.expires_at <= func.now())
            result = await session.execute(stmt)
            expired_entries = result.scalars().all()

            deleted_count = len(expired_entries)
            for entry in expired_entries:
                await session.delete(entry)

            await session.commit()
            self.logger.info(f"Cleaned up {deleted_count} expired cache entries")
            return deleted_count

    async def get_database_stats_async(self) -> Dict[str, Any]:
        """Get database statistics and health information asynchronously."""
        try:
            async with self.get_async_session() as session:
                # Get table counts
                scan_results_stmt = select(func.count()).select_from(ScanResult)
                cache_stmt = select(func.count()).select_from(ScanCache)

                scan_results_count = await session.scalar(scan_results_stmt)
                cache_entries_count = await session.scalar(cache_stmt)

                # Get recent activity (last 24 hours)
                yesterday = datetime.utcnow() - timedelta(days=1)
                recent_scans_stmt = select(func.count()).select_from(ScanResult).where(
                    ScanResult.created_at >= yesterday
                )
                recent_scans = await session.scalar(recent_scans_stmt)

                return {
                    "database_type": self.config.database.url.split("://")[0],
                    "scan_results_count": scan_results_count,
                    "cache_entries_count": cache_entries_count,
                    "recent_scans_24h": recent_scans,
                    "connection_pool_size": self.config.database.pool_size,
                    "status": "healthy",
                }

        except Exception as e:
            self.logger.error(f"Database health check failed: {e}")
            return {"status": "unhealthy", "error": str(e)}

    # Convenience methods for backward compatibility
    async def store_scan_result(
        self,
        scan_type: str,
        target_path: str,
        status: str,
        results: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None,
        scan_duration: Optional[int] = None,
        file_count: Optional[int] = None,
    ) -> int:
        """Store scan result (async by default)."""
        return await self.store_scan_result_async(
            scan_type, target_path, status, results, error_message, scan_duration, file_count
        )

    async def get_scan_results(
        self, scan_type: Optional[str] = None, limit: int = 50, offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Get scan results (async by default)."""
        return await self.get_scan_results_async(scan_type, limit, offset)

    async def get_scan_cache(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached scan result (async by default)."""
        return await self.get_scan_cache_async(cache_key)

    async def set_scan_cache(
        self,
        cache_key: str,
        scan_type: str,
        target_path: str,
        results: Dict[str, Any],
        ttl_seconds: int = 3600,
    ) -> None:
        """Set cached scan result (async by default)."""
        await self.set_scan_cache_async(cache_key, scan_type, target_path, results, ttl_seconds)

    async def cleanup_expired_cache(self) -> int:
        """Clean up expired cache entries (async by default)."""
        return await self.cleanup_expired_cache_async()

    async def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics (async by default)."""
        return await self.get_database_stats_async()