# DECOYABLE Scanners Module
# Refactored for dependency injection and single-responsibility architecture

from .deps import missing_dependencies as missing_dependencies_legacy
from .interfaces import ScannerType, ScanReport, ScanResult, ScanSummary
from .sast import scan_sast as scan_sast_legacy

# Backward compatibility - these will be deprecated
from .secrets import scan_paths as scan_secrets_legacy
from .service import ScannerService, scan_dependencies, scan_sast, scan_secrets

__all__ = [
    # New architecture
    "ScannerService",
    "ScannerType",
    "ScanResult",
    "ScanSummary",
    "ScanReport",
    "scan_secrets",
    "scan_dependencies",
    "scan_sast",
    # Legacy (deprecated)
    "scan_secrets_legacy",
    "missing_dependencies_legacy",
    "scan_sast_legacy",
]
