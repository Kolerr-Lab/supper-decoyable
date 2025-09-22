# DECOYABLE Scanners Module
# Refactored for dependency injection and single-responsibility architecture

from .service import ScannerService, scan_secrets, scan_dependencies, scan_sast
from .interfaces import ScannerType, ScanResult, ScanSummary, ScanReport

# Backward compatibility - these will be deprecated
from .secrets import scan_paths as scan_secrets_legacy
from .deps import missing_dependencies as missing_dependencies_legacy
from .sast import scan_sast as scan_sast_legacy

__all__ = [
    # New architecture
    'ScannerService',
    'ScannerType',
    'ScanResult',
    'ScanSummary',
    'ScanReport',
    'scan_secrets',
    'scan_dependencies',
    'scan_sast',

    # Legacy (deprecated)
    'scan_secrets_legacy',
    'missing_dependencies_legacy',
    'scan_sast_legacy',
]
