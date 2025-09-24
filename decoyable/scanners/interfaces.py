"""
Scanner service interfaces and base classes.

This module defines the interfaces and base classes for all security scanners
in the DECOYABLE system, providing a consistent API and dependency injection support.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Union

from decoyable.core.logging import get_logger


class ScanResult(Enum):
    """Result status of a scan operation."""

    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"


class ScannerType(Enum):
    """Types of security scanners available."""

    SECRETS = "secrets"
    DEPENDENCIES = "dependencies"
    SAST = "sast"


@dataclass
class ScanSummary:
    """Summary of scan results."""

    scanner_type: ScannerType
    total_items: int = 0
    issues_found: int = 0
    scan_time_ms: float = 0.0
    result: ScanResult = ScanResult.SUCCESS
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class ScanReport:
    """Complete scan report containing results and summary."""

    scanner_type: ScannerType
    results: List[Any]  # Specific result types per scanner
    summary: ScanSummary
    timestamp: float
    scanner_version: str = "1.0.0"


class ScannerConfig(Protocol):
    """Protocol for scanner configuration."""

    enabled: bool
    timeout_seconds: int
    max_file_size_mb: int
    exclude_patterns: List[str]


class BaseScanner(ABC):
    """Abstract base class for all security scanners."""

    def __init__(self, scanner_type: ScannerType, config: ScannerConfig):
        self.scanner_type = scanner_type
        self.config = config
        self.logger = get_logger(f"scanner.{scanner_type.value}")

    @abstractmethod
    async def scan_path(self, path: Union[str, Path], **kwargs) -> ScanReport:
        """
        Scan a file system path for security issues.

        Args:
            path: Path to scan
            **kwargs: Scanner-specific options

        Returns:
            ScanReport with results and summary
        """
        pass

    @abstractmethod
    async def scan_content(self, content: str, filename: Optional[str] = None, **kwargs) -> List[Any]:
        """
        Scan content string for security issues.

        Args:
            content: Content to scan
            filename: Optional filename for context
            **kwargs: Scanner-specific options

        Returns:
            List of findings/issues
        """
        pass

    def is_enabled(self) -> bool:
        """Check if this scanner is enabled."""
        return self.config.enabled

    def should_scan_file(self, file_path: Path) -> bool:
        """Check if a file should be scanned based on configuration."""
        if file_path.stat().st_size > self.config.max_file_size_mb * 1024 * 1024:
            self.logger.debug(f"Skipping large file: {file_path} ({file_path.stat().st_size} bytes)")
            return False

        # Check exclude patterns
        file_str = str(file_path)
        for pattern in self.config.exclude_patterns:
            if pattern in file_str:
                self.logger.debug(f"Skipping excluded file: {file_path} (matches {pattern})")
                return False

        return True

    async def _create_report(
        self,
        results: List[Any],
        scan_time_ms: float,
        result: ScanResult = ScanResult.SUCCESS,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ScanReport:
        """Create a standardized scan report."""
        summary = ScanSummary(
            scanner_type=self.scanner_type,
            total_items=len(results),
            issues_found=len([r for r in results if hasattr(r, "is_issue") and r.is_issue]) if results else 0,
            scan_time_ms=scan_time_ms,
            result=result,
            metadata=metadata,
        )

        return ScanReport(
            scanner_type=self.scanner_type, results=results, summary=summary, timestamp=__import__("time").time()
        )
