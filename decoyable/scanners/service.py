"""
Scanner service that orchestrates all security scanners with dependency injection.
"""

import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from decoyable.core.config import Settings
from decoyable.core.logging import get_logger, LoggingService
from decoyable.core.cache_service import CacheService
from decoyable.scanners.deps_scanner import DependenciesScanner, DependenciesScannerConfig, DependencyIssue
from decoyable.scanners.interfaces import ScanReport, ScannerType
from decoyable.scanners.sast_scanner import SASTScanner, SASTScannerConfig, Vulnerability
from decoyable.scanners.secrets_scanner import SecretsScanner, SecretsScannerConfig, SecretFinding


class ScannerService:
    """Service that orchestrates all security scanners."""

    def __init__(self, config: Settings, logging_service: LoggingService, cache_service: Optional[CacheService] = None):
        self.config = config
        self.logger = get_logger("scanner.service")
        self.cache_service = cache_service

        # Initialize scanner configurations
        self.secrets_config = SecretsScannerConfig(
            enabled=config.scanners.secrets_enabled,
            timeout_seconds=config.scanners.timeout_seconds,
            max_file_size_mb=config.scanners.max_file_size_mb,
            exclude_patterns=config.scanners.exclude_patterns,
            min_confidence=config.scanners.min_confidence
        )

        self.deps_config = DependenciesScannerConfig(
            enabled=config.scanners.deps_enabled,
            timeout_seconds=config.scanners.timeout_seconds,
            max_file_size_mb=config.scanners.max_file_size_mb,
            exclude_patterns=config.scanners.exclude_patterns,
            check_missing_imports=config.scanners.check_missing_imports,
            check_unused_dependencies=config.scanners.check_unused_dependencies
        )

        self.sast_config = SASTScannerConfig(
            enabled=config.scanners.sast_enabled,
            timeout_seconds=config.scanners.timeout_seconds,
            max_file_size_mb=config.scanners.max_file_size_mb,
            exclude_patterns=config.scanners.exclude_patterns,
            min_confidence=config.scanners.min_confidence,
            severity_threshold=config.scanners.severity_threshold
        )

        # Initialize scanners
        self.secrets_scanner = SecretsScanner(self.secrets_config)
        self.deps_scanner = DependenciesScanner(self.deps_config)
        self.sast_scanner = SASTScanner(self.sast_config)

        self._all_scanners = {
            ScannerType.SECRETS: self.secrets_scanner,
            ScannerType.DEPENDENCIES: self.deps_scanner,
            ScannerType.SAST: self.sast_scanner
        }

    async def scan_all(self, path: Union[str, "Path"], **kwargs) -> Dict[ScannerType, ScanReport]:
        """Run all enabled scanners on a path."""
        self.logger.info(f"Starting comprehensive scan on: {path}")

        results = {}
        enabled_scanners = [(stype, scanner) for stype, scanner in self._all_scanners.items() if scanner.is_enabled()]

        if not enabled_scanners:
            self.logger.warning("No scanners are enabled")
            return results

        # Run scanners concurrently
        tasks = []
        for scanner_type, scanner in enabled_scanners:
            task = asyncio.create_task(self._scan_with_type(scanner_type, scanner, path, **kwargs))
            tasks.append((scanner_type, task))

        # Wait for all scans to complete
        for scanner_type, task in tasks:
            try:
                report = await task
                results[scanner_type] = report
                self.logger.info(f"{scanner_type.value} scan completed: {len(report.results)} issues found")
            except Exception as e:
                self.logger.error(f"Error in {scanner_type.value} scan: {e}")
                # Create a failure report
                results[scanner_type] = ScanReport(
                    scanner_type=scanner_type,
                    results=[],
                    summary=type('Summary', (), {
                        'total_items': 0,
                        'issues_found': 0,
                        'scan_time_ms': 0.0,
                        'result': 'failure',
                        'metadata': {'error': str(e)}
                    })(),
                    timestamp=asyncio.get_event_loop().time()
                )

        return results

    async def scan_secrets(self, path: Union[str, "Path"], **kwargs) -> ScanReport:
        """Scan for secrets only."""
        if self.cache_service:
            # Use cached version with 30 minute TTL
            return await self.cache_service.cached(
                ttl=1800,
                key_prefix="secrets",
                scan_type="secrets",
                persist=True
            )(self._scan_secrets_uncached)(path, **kwargs)
        else:
            return await self._scan_secrets_uncached(path, **kwargs)

    async def _scan_secrets_uncached(self, path: Union[str, "Path"], **kwargs) -> ScanReport:
        """Uncached secrets scan implementation."""
        return await self.secrets_scanner.scan_path(path, **kwargs)

    async def scan_dependencies(self, path: Union[str, "Path"], **kwargs) -> ScanReport:
        """Scan for dependency issues only."""
        if self.cache_service:
            # Use cached version with 1 hour TTL
            return await self.cache_service.cached(
                ttl=3600,
                key_prefix="deps",
                scan_type="dependencies",
                persist=True
            )(self._scan_dependencies_uncached)(path, **kwargs)
        else:
            return await self._scan_dependencies_uncached(path, **kwargs)

    async def _scan_dependencies_uncached(self, path: Union[str, "Path"], **kwargs) -> ScanReport:
        """Uncached dependencies scan implementation."""
        return await self.deps_scanner.scan_path(path, **kwargs)

    async def scan_sast(self, path: Union[str, "Path"], **kwargs) -> ScanReport:
        """Scan for security vulnerabilities only."""
        if self.cache_service:
            # Use cached version with 30 minute TTL
            return await self.cache_service.cached(
                ttl=1800,
                key_prefix="sast",
                scan_type="sast",
                persist=True
            )(self._scan_sast_uncached)(path, **kwargs)
        else:
            return await self._scan_sast_uncached(path, **kwargs)

    async def _scan_sast_uncached(self, path: Union[str, "Path"], **kwargs) -> ScanReport:
        """Uncached SAST scan implementation."""
        return await self.sast_scanner.scan_path(path, **kwargs)

    async def _scan_with_type(self, scanner_type: ScannerType, scanner, path: Union[str, "Path"], **kwargs) -> ScanReport:
        """Helper to scan with a specific scanner type."""
        with scanner.logger.get_logger(f"scan.{scanner_type.value}").correlation_context() as corr_id:
            scanner.logger.info(f"Starting {scanner_type.value} scan", extra={'path': str(path)})
            report = await scanner.scan_path(path, **kwargs)
            scanner.logger.info(f"Completed {scanner_type.value} scan", extra={
                'issues_found': len(report.results),
                'scan_time_ms': report.summary.scan_time_ms
            })
            return report

    def get_scanner_status(self) -> Dict[str, bool]:
        """Get the enabled status of all scanners."""
        return {
            scanner_type.value: scanner.is_enabled()
            for scanner_type, scanner in self._all_scanners.items()
        }

    def get_scan_summary(self, results: Dict[ScannerType, ScanReport]) -> Dict[str, Any]:
        """Generate a summary of all scan results."""
        total_issues = 0
        total_scan_time = 0.0
        scanner_summaries = {}

        for scanner_type, report in results.items():
            total_issues += len(report.results)
            total_scan_time += report.summary.scan_time_ms
            scanner_summaries[scanner_type.value] = {
                'issues_found': len(report.results),
                'scan_time_ms': report.summary.scan_time_ms,
                'result': report.summary.result.value,
                'metadata': report.summary.metadata or {}
            }

        return {
            'total_issues': total_issues,
            'total_scan_time_ms': total_scan_time,
            'scanner_summaries': scanner_summaries,
            'timestamp': asyncio.get_event_loop().time()
        }


# Convenience functions for backward compatibility
async def scan_secrets(path: Union[str, "Path"]) -> List[SecretFinding]:
    """Backward compatibility function for secrets scanning."""
    from decoyable.core.registry import ServiceRegistry
    registry = ServiceRegistry()
    config = registry.get_by_name('config')
    logging_service = registry.get_by_name('logging')

    if not config or not logging_service:
        raise RuntimeError("Services not properly initialized")

    service = ScannerService(config, logging_service)
    report = await service.scan_secrets(path)
    return report.results


async def scan_dependencies(path: Union[str, "Path"]) -> tuple[List[str], Dict[str, List[str]]]:
    """Backward compatibility function for dependency scanning."""
    from decoyable.core.registry import ServiceRegistry
    registry = ServiceRegistry()
    config = registry.get_by_name('config')
    logging_service = registry.get_by_name('logging')

    if not config or not logging_service:
        raise RuntimeError("Services not properly initialized")

    service = ScannerService(config, logging_service)
    report = await service.scan_dependencies(path)

    # Convert to old format
    missing_imports = [issue.module_name for issue in report.results if issue.issue_type == "missing_import"]
    import_mapping = {}

    return missing_imports, import_mapping


async def scan_sast(path: Union[str, "Path"]) -> Dict[str, Any]:
    """Backward compatibility function for SAST scanning."""
    from decoyable.core.registry import ServiceRegistry
    registry = ServiceRegistry()
    config = registry.get_by_name('config')
    logging_service = registry.get_by_name('logging')

    if not config or not logging_service:
        raise RuntimeError("Services not properly initialized")

    service = ScannerService(config, logging_service)
    report = await service.scan_sast(path)

    # Convert to old format
    return {
        'vulnerabilities': report.results,
        'summary': {
            'total': len(report.results),
            'critical': len([v for v in report.results if v.severity.value == 'CRITICAL']),
            'high': len([v for v in report.results if v.severity.value == 'HIGH']),
            'medium': len([v for v in report.results if v.severity.value == 'MEDIUM']),
            'low': len([v for v in report.results if v.severity.value == 'LOW']),
            'info': len([v for v in report.results if v.severity.value == 'INFO'])
        }
    }