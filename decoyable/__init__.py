"""DECOYABLE - Enterprise-grade cybersecurity scanning tool."""

__version__ = "0.1.0"
__author__ = "DECOYABLE Team"
__description__ = "Enterprise-grade cybersecurity scanning tool for secrets, dependencies, and vulnerabilities"

from .core import registry
from .scanners import deps, secrets

__all__ = ["registry", "deps", "secrets", "__version__"]
