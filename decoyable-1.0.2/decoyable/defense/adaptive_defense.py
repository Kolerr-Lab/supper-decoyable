"""
decoyable/defense/adaptive_defense.py

Adaptive defense system for DECOYABLE.
Manages dynamic patterns, IP blocking, and decoy endpoints.
"""

import logging
from typing import Dict, List

from .patterns import ATTACK_PATTERNS

logger = logging.getLogger(__name__)


class AdaptiveDefense:
    """Manages adaptive defense rules and patterns."""

    def __init__(self):
        self.dynamic_patterns: Dict[str, List[str]] = {}
        self.blocked_ips: set = set()
        self.decoy_endpoints: set = set()

    def add_pattern(self, attack_type: str, pattern: str) -> None:
        """Add a new pattern for attack detection."""
        if attack_type not in self.dynamic_patterns:
            self.dynamic_patterns[attack_type] = []
        if pattern not in self.dynamic_patterns[attack_type]:
            self.dynamic_patterns[attack_type].append(pattern)
            logger.info(f"Added dynamic pattern for {attack_type}: {pattern}")

    def block_ip(self, ip: str) -> None:
        """Mark IP for blocking."""
        self.blocked_ips.add(ip)
        logger.info(f"Marked IP for blocking: {ip}")

    def add_decoy_endpoint(self, endpoint: str) -> None:
        """Add a new decoy endpoint."""
        self.decoy_endpoints.add(endpoint)
        logger.info(f"Added decoy endpoint: {endpoint}")

    def get_all_patterns(self) -> Dict[str, List[str]]:
        """Get all patterns (static + dynamic)."""
        all_patterns = ATTACK_PATTERNS.copy()
        for attack_type, patterns in self.dynamic_patterns.items():
            if attack_type not in all_patterns:
                all_patterns[attack_type] = []
            all_patterns[attack_type].extend(patterns)
        return all_patterns


# Global adaptive defense instance
adaptive_defense = AdaptiveDefense()
