"""
Structured logging system for DECOYABLE.

This module provides a comprehensive logging service with:
- JSON formatting for structured logs
- Correlation IDs for request tracing
- Configurable log levels
- Performance monitoring
- Context-aware logging
"""

import json
import logging
import logging.handlers
import sys
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Dict, Optional

from decoyable.core.config import Settings

# Context variables for correlation IDs and request context
correlation_id: ContextVar[Optional[str]] = ContextVar("correlation_id", default=None)
request_context: ContextVar[Optional[Dict[str, Any]]] = ContextVar("request_context", default=None)


class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging."""

    def __init__(self, include_extra: bool = True):
        super().__init__()
        self.include_extra = include_extra

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        # Get correlation ID from context
        corr_id = correlation_id.get()

        # Base log entry
        log_entry = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S") + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add correlation ID if present
        if corr_id:
            log_entry["correlation_id"] = corr_id

        # Add request context if present
        ctx = request_context.get()
        if ctx:
            log_entry["context"] = ctx

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Add extra fields from record
        if self.include_extra:
            for key, value in record.__dict__.items():
                if key not in {
                    "name",
                    "msg",
                    "args",
                    "levelname",
                    "levelno",
                    "pathname",
                    "filename",
                    "module",
                    "exc_info",
                    "exc_text",
                    "stack_info",
                    "lineno",
                    "funcName",
                    "created",
                    "msecs",
                    "relativeCreated",
                    "thread",
                    "threadName",
                    "processName",
                    "process",
                    "message",
                }:
                    log_entry[key] = value

        return json.dumps(log_entry, default=str, separators=(",", ":"))


class PerformanceFormatter(logging.Formatter):
    """Formatter for performance monitoring logs."""

    def format(self, record: logging.LogRecord) -> str:
        """Format performance log record."""
        corr_id = correlation_id.get()

        perf_entry = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S") + "Z",
            "level": "PERFORMANCE",
            "logger": record.name,
            "operation": getattr(record, "operation", "unknown"),
            "duration_ms": getattr(record, "duration_ms", 0),
            "success": getattr(record, "success", True),
        }

        if corr_id:
            perf_entry["correlation_id"] = corr_id

        # Add extra performance metrics
        for key in ["cpu_percent", "memory_mb", "io_read_mb", "io_write_mb"]:
            if hasattr(record, key):
                perf_entry[key] = getattr(record, key)

        return json.dumps(perf_entry, default=str, separators=(",", ":"))


class LoggerAdapter(logging.LoggerAdapter):
    """Logger adapter that adds context to log records."""

    def __init__(self, logger: logging.Logger, extra: Optional[Dict[str, Any]] = None):
        super().__init__(logger, extra or {})

    def process(self, msg: str, kwargs: Any) -> tuple[str, Any]:
        """Process log message with context."""
        # Add correlation ID to extra
        corr_id = correlation_id.get()
        if corr_id:
            kwargs.setdefault("extra", {})["correlation_id"] = corr_id

        # Add request context
        ctx = request_context.get()
        if ctx:
            kwargs.setdefault("extra", {}).update(ctx)

        return msg, kwargs


class LoggingService:
    """Centralized logging service with structured logging capabilities."""

    def __init__(self, config: Settings):
        self.config = config
        self._lock = threading.RLock()
        self._loggers: Dict[str, LoggerAdapter] = {}
        self._setup_complete = False

    def setup_logging(self) -> None:
        """Setup the logging system with configuration."""
        with self._lock:
            if self._setup_complete:
                return

            # Clear existing handlers
            root_logger = logging.getLogger()
            root_logger.handlers.clear()

            # Set root logger level
            root_logger.setLevel(getattr(logging, self.config.logging.level.upper(), logging.INFO))

            # Create formatters
            structured_formatter = StructuredFormatter()
            performance_formatter = PerformanceFormatter()

            # Console handler for structured logs
            if self.config.logging.console_enabled:
                console_handler = logging.StreamHandler(sys.stdout)
                console_handler.setLevel(getattr(logging, self.config.logging.console_level.upper(), logging.INFO))
                console_handler.setFormatter(structured_formatter)
                root_logger.addHandler(console_handler)

            # File handler for structured logs
            if self.config.logging.file_enabled and self.config.logging.file_path:
                log_path = Path(self.config.logging.file_path)
                log_path.parent.mkdir(parents=True, exist_ok=True)

                file_handler = logging.handlers.RotatingFileHandler(
                    filename=str(log_path),
                    maxBytes=self.config.logging.file_max_size_mb * 1024 * 1024,
                    backupCount=self.config.logging.file_backup_count,
                    encoding="utf-8",
                )
                file_handler.setLevel(getattr(logging, self.config.logging.file_level.upper(), logging.INFO))
                file_handler.setFormatter(structured_formatter)
                root_logger.addHandler(file_handler)

            # Performance logging handler
            if self.config.logging.performance_enabled and self.config.logging.performance_file_path:
                perf_path = Path(self.config.logging.performance_file_path)
                perf_path.parent.mkdir(parents=True, exist_ok=True)

                perf_handler = logging.handlers.RotatingFileHandler(
                    filename=str(perf_path),
                    maxBytes=self.config.logging.performance_max_size_mb * 1024 * 1024,
                    backupCount=self.config.logging.performance_backup_count,
                    encoding="utf-8",
                )
                perf_handler.setLevel(logging.INFO)
                perf_handler.setFormatter(performance_formatter)
                perf_handler.addFilter(lambda record: hasattr(record, "operation"))
                root_logger.addHandler(perf_handler)

            self._setup_complete = True

    def get_logger(self, name: str) -> LoggerAdapter:
        """Get a structured logger for the given name."""
        with self._lock:
            if name not in self._loggers:
                logger = logging.getLogger(name)
                self._loggers[name] = LoggerAdapter(logger)
            return self._loggers[name]

    @contextmanager
    def correlation_context(self, corr_id: Optional[str] = None):
        """Context manager for setting correlation ID."""
        if corr_id is None:
            corr_id = f"{int(time.time() * 1000000)}"

        token = correlation_id.set(corr_id)
        try:
            yield corr_id
        finally:
            correlation_id.reset(token)

    @contextmanager
    def request_context(self, **context):
        """Context manager for setting request context."""
        token = request_context.set(context)
        try:
            yield
        finally:
            request_context.reset(token)

    def log_performance(self, operation: str, duration_ms: float, success: bool = True, **metrics):
        """Log performance metrics."""
        logger = self.get_logger("performance")
        extra = {"operation": operation, "duration_ms": duration_ms, "success": success, **metrics}
        logger.info(f"Performance: {operation}", extra=extra)


# Global logging service instance
_logging_service: Optional[LoggingService] = None


def get_logging_service() -> LoggingService:
    """Get the global logging service instance."""
    if _logging_service is None:
        raise RuntimeError("Logging service not initialized. Call setup_logging_service() first.")
    return _logging_service


def setup_logging_service(config: Settings) -> LoggingService:
    """Setup and return the global logging service."""
    global _logging_service
    if _logging_service is None:
        _logging_service = LoggingService(config)
        _logging_service.setup_logging()
    return _logging_service


def get_logger(name: str) -> LoggerAdapter:
    """Get a structured logger (convenience function)."""
    return get_logging_service().get_logger(name)
