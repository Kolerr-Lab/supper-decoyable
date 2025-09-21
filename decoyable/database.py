"""Database connection management and optimization for DECOYABLE."""

import os
import logging
from typing import Optional, Any, Dict, List
from contextlib import contextmanager
from sqlalchemy import create_engine, pool
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Boolean
from sqlalchemy.sql import func
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger(__name__)

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


class DatabaseManager:
    """Database connection manager with connection pooling and optimization."""

    def __init__(self, database_url: Optional[str] = None):
        """
        Initialize database manager.

        Args:
            database_url: Database connection URL
        """
        self.database_url = database_url or os.getenv("DATABASE_URL", "sqlite:///decoyable.db")
        self.engine = None
        self.SessionLocal = None
        self._initialized = False

    def initialize(self) -> None:
        """Initialize database connection and create tables."""
        if self._initialized:
            return

        try:
            # Configure connection pooling based on database type
            if self.database_url.startswith("postgresql"):
                # PostgreSQL connection pooling
                self.engine = create_engine(
                    self.database_url,
                    poolclass=pool.QueuePool,
                    pool_size=10,  # Maximum connections in pool
                    max_overflow=20,  # Maximum overflow connections
                    pool_timeout=30,  # Timeout for getting connection from pool
                    pool_recycle=3600,  # Recycle connections after 1 hour
                    pool_pre_ping=True,  # Test connections before use
                    echo=False  # Set to True for SQL debugging
                )
            elif self.database_url.startswith("mysql"):
                # MySQL connection pooling
                self.engine = create_engine(
                    self.database_url,
                    poolclass=pool.QueuePool,
                    pool_size=10,
                    max_overflow=20,
                    pool_timeout=30,
                    pool_recycle=3600,
                    pool_pre_ping=True,
                    echo=False
                )
            else:
                # SQLite (file-based, no pooling needed)
                self.engine = create_engine(
                    self.database_url,
                    poolclass=pool.NullPool,  # No pooling for SQLite
                    echo=False
                )

            # Create session factory
            self.SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=self.engine
            )

            # Create tables
            Base.metadata.create_all(bind=self.engine)

            self._initialized = True
            logger.info("Database initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise

    @contextmanager
    def get_session(self):
        """Get database session with automatic cleanup."""
        if not self._initialized:
            self.initialize()

        session = self.SessionLocal()
        try:
            yield session
        except Exception as e:
            session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            session.close()

    def store_scan_result(self, scan_type: str, target_path: str, status: str,
                         results: Optional[Dict[str, Any]] = None,
                         error_message: Optional[str] = None,
                         scan_duration: Optional[int] = None,
                         file_count: Optional[int] = None) -> int:
        """Store scan result in database."""
        with self.get_session() as session:
            scan_result = ScanResult(
                scan_type=scan_type,
                target_path=target_path,
                status=status,
                results=results,
                error_message=error_message,
                scan_duration=scan_duration,
                file_count=file_count
            )
            session.add(scan_result)
            session.commit()
            return scan_result.id

    def get_scan_results(self, scan_type: Optional[str] = None,
                        limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Retrieve scan results from database."""
        with self.get_session() as session:
            query = session.query(ScanResult)

            if scan_type:
                query = query.filter(ScanResult.scan_type == scan_type)

            query = query.order_by(ScanResult.created_at.desc()).limit(limit).offset(offset)

            results = []
            for result in query.all():
                results.append({
                    "id": result.id,
                    "scan_type": result.scan_type,
                    "target_path": result.target_path,
                    "status": result.status,
                    "results": result.results,
                    "error_message": result.error_message,
                    "created_at": result.created_at.isoformat() if result.created_at else None,
                    "scan_duration": result.scan_duration,
                    "file_count": result.file_count
                })

            return results

    def get_scan_cache(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached scan result."""
        with self.get_session() as session:
            cache_entry = session.query(ScanCache).filter(
                ScanCache.cache_key == cache_key,
                ScanCache.expires_at > func.now()
            ).first()

            if cache_entry:
                # Update hit count
                cache_entry.hit_count += 1
                session.commit()

                return {
                    "scan_type": cache_entry.scan_type,
                    "target_path": cache_entry.target_path,
                    "results": cache_entry.results,
                    "created_at": cache_entry.created_at.isoformat() if cache_entry.created_at else None,
                    "hit_count": cache_entry.hit_count
                }

        return None

    def set_scan_cache(self, cache_key: str, scan_type: str, target_path: str,
                      results: Dict[str, Any], ttl_seconds: int = 3600) -> None:
        """Set cached scan result."""
        from datetime import datetime, timedelta

        expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)

        with self.get_session() as session:
            # Check if cache entry already exists
            existing = session.query(ScanCache).filter(
                ScanCache.cache_key == cache_key
            ).first()

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
                    expires_at=expires_at
                )
                session.add(cache_entry)

            session.commit()

    def cleanup_expired_cache(self) -> int:
        """Clean up expired cache entries. Returns number of deleted entries."""
        with self.get_session() as session:
            deleted_count = session.query(ScanCache).filter(
                ScanCache.expires_at <= func.now()
            ).delete()

            session.commit()
            logger.info(f"Cleaned up {deleted_count} expired cache entries")
            return deleted_count

    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics and health information."""
        try:
            with self.get_session() as session:
                # Get table counts
                scan_results_count = session.query(ScanResult).count()
                cache_entries_count = session.query(ScanCache).count()

                # Get recent activity
                recent_scans = session.query(ScanResult).filter(
                    ScanResult.created_at >= func.now() - func.interval('1 day')
                ).count()

                return {
                    "database_type": self.database_url.split("://")[0],
                    "scan_results_count": scan_results_count,
                    "cache_entries_count": cache_entries_count,
                    "recent_scans_24h": recent_scans,
                    "connection_pool_size": getattr(self.engine.pool, 'size', 'N/A') if hasattr(self.engine, 'pool') else 'N/A',
                    "status": "healthy"
                }

        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e)
            }


# Global database manager instance
_db_manager: Optional[DatabaseManager] = None


def get_database_manager() -> DatabaseManager:
    """Get or create global database manager instance."""
    global _db_manager

    if _db_manager is None:
        database_url = os.getenv("DATABASE_URL")
        _db_manager = DatabaseManager(database_url=database_url)
        _db_manager.initialize()

    return _db_manager


def store_scan_result(scan_type: str, target_path: str, status: str, **kwargs) -> int:
    """Convenience function to store scan result."""
    db = get_database_manager()
    return db.store_scan_result(scan_type, target_path, status, **kwargs)


def get_scan_results(scan_type: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    """Convenience function to get scan results."""
    db = get_database_manager()
    return db.get_scan_results(scan_type=scan_type, limit=limit)