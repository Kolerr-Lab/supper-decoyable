"""
SAST (Static Application Security Testing) scanner implementation with dependency injection support.
"""

import asyncio
import os
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from decoyable.scanners.interfaces import BaseScanner, ScannerType, ScanReport, ScanResult


class VulnerabilitySeverity(Enum):
    """Severity levels for vulnerabilities."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnerabilityType(Enum):
    """Types of vulnerabilities that can be detected."""

    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    INSECURE_RANDOM = "INSECURE_RANDOM"
    HARDCODED_SECRET = "HARDCODED_SECRET"
    WEAK_CRYPTO = "WEAK_CRYPTO"
    DESERIALIZATION = "DESERIALIZATION"
    SSRF = "SSRF"
    XXE = "XXE"
    INSECURE_HTTP = "INSECURE_HTTP"
    DEBUG_ENABLED = "DEBUG_ENABLED"
    EVAL_USAGE = "EVAL_USAGE"


@dataclass
class Vulnerability:
    """Represents a security vulnerability found in code."""

    file_path: str
    line_number: int
    vulnerability_type: VulnerabilityType
    severity: VulnerabilitySeverity
    description: str
    code_snippet: str
    recommendation: str
    confidence: float = 1.0
    cwe_id: Optional[str] = None
    is_issue: bool = True


@dataclass
class SASTScannerConfig:
    """Configuration for the SAST scanner."""

    enabled: bool = True
    timeout_seconds: int = 300
    max_file_size_mb: int = 5
    exclude_patterns: List[str] = None
    min_confidence: float = 0.7
    severity_threshold: str = "LOW"  # Minimum severity to report
    enable_experimental_rules: bool = False

    def __post_init__(self):
        if self.exclude_patterns is None:
            self.exclude_patterns = [".git", "__pycache__", "node_modules", ".venv", "venv", "test", "tests"]


class SASTScanner(BaseScanner):
    """Static Application Security Testing scanner with comprehensive vulnerability detection."""

    def __init__(self, config: SASTScannerConfig):
        super().__init__(ScannerType.SAST, config)
        self.config: SASTScannerConfig = config
        self._rules = self._compile_rules()

    def _compile_rules(self) -> List[Dict[str, Any]]:
        """Compile security rules for vulnerability detection."""
        rules = [
            # SQL Injection patterns
            {
                "type": VulnerabilityType.SQL_INJECTION,
                "severity": VulnerabilitySeverity.HIGH,
                "pattern": re.compile(
                    r'(?:execute|executemany|raw)\s*\(\s*["\'](.*?(?:SELECT|INSERT|UPDATE|DELETE).*?)["\']',
                    re.IGNORECASE | re.DOTALL,
                ),
                "description": "Potential SQL injection vulnerability",
                "recommendation": "Use parameterized queries or ORM instead of string formatting",
                "cwe_id": "CWE-89",
            },
            # XSS patterns
            {
                "type": VulnerabilityType.XSS,
                "severity": VulnerabilitySeverity.HIGH,
                "pattern": re.compile(r"innerHTML\s*\+?\s*=", re.IGNORECASE),
                "description": "Potential XSS vulnerability with innerHTML assignment",
                "recommendation": "Use textContent or sanitize HTML input",
                "cwe_id": "CWE-79",
            },
            # Command injection
            {
                "type": VulnerabilityType.COMMAND_INJECTION,
                "severity": VulnerabilitySeverity.CRITICAL,
                "pattern": re.compile(
                    r'(?:subprocess\.|os\.system|os\.popen|commands\.)\w*\(\s*["\'](.*?(?:\$|%s|\{.*?\}).*?)["\']',
                    re.DOTALL,
                ),
                "description": "Potential command injection vulnerability",
                "recommendation": "Use subprocess with shell=False and proper argument lists",
                "cwe_id": "CWE-78",
            },
            # Path traversal
            {
                "type": VulnerabilityType.PATH_TRAVERSAL,
                "severity": VulnerabilitySeverity.HIGH,
                "pattern": re.compile(r'open\s*\(\s*["\'](.*?(?:\.\./|\.\.\\).*?)["\']', re.IGNORECASE),
                "description": "Potential path traversal vulnerability",
                "recommendation": "Validate and sanitize file paths",
                "cwe_id": "CWE-22",
            },
            # Insecure random
            {
                "type": VulnerabilityType.INSECURE_RANDOM,
                "severity": VulnerabilitySeverity.MEDIUM,
                "pattern": re.compile(
                    r"import\s+random\n.*random\.(?:randint|choice|sample)", re.MULTILINE | re.DOTALL
                ),
                "description": "Using insecure random number generation",
                "recommendation": "Use secrets module for cryptographic purposes",
                "cwe_id": "CWE-338",
            },
            # Hardcoded secrets
            {
                "type": VulnerabilityType.HARDCODED_SECRET,
                "severity": VulnerabilitySeverity.MEDIUM,
                "pattern": re.compile(r'(?:password|secret|key|token)\s*=\s*["\'][^"\']{10,}["\']', re.IGNORECASE),
                "description": "Potential hardcoded secret or credential",
                "recommendation": "Use environment variables or secure credential storage",
                "cwe_id": "CWE-798",
            },
            # Weak crypto
            {
                "type": VulnerabilityType.WEAK_CRYPTO,
                "severity": VulnerabilitySeverity.MEDIUM,
                "pattern": re.compile(r"(?:md5|sha1)\s*\(", re.IGNORECASE),
                "description": "Using weak cryptographic hash function",
                "recommendation": "Use SHA-256 or stronger hashing algorithms",
                "cwe_id": "CWE-327",
            },
            # Insecure deserialization
            {
                "type": VulnerabilityType.DESERIALIZATION,
                "severity": VulnerabilitySeverity.HIGH,
                "pattern": re.compile(r"(?:pickle|cPickle)\.loads?\s*\(", re.IGNORECASE),
                "description": "Potential insecure deserialization vulnerability",
                "recommendation": "Avoid pickle for untrusted data, use JSON or secure alternatives",
                "cwe_id": "CWE-502",
            },
            # SSRF
            {
                "type": VulnerabilityType.SSRF,
                "severity": VulnerabilitySeverity.HIGH,
                "pattern": re.compile(
                    r'(?:requests|urllib|httpx)\.\w+\(\s*["\'](.*?(?:\{.*?\}|\$.*?).*?)["\']', re.DOTALL
                ),
                "description": "Potential Server-Side Request Forgery vulnerability",
                "recommendation": "Validate and whitelist URLs, avoid user-controlled URLs",
                "cwe_id": "CWE-918",
            },
            # Insecure HTTP
            {
                "type": VulnerabilityType.INSECURE_HTTP,
                "severity": VulnerabilitySeverity.MEDIUM,
                "pattern": re.compile(r'https?://[^\s"\']*', re.IGNORECASE),
                "description": "HTTP URL found (should use HTTPS)",
                "recommendation": "Use HTTPS instead of HTTP for secure communication",
                "cwe_id": "CWE-319",
            },
            # Debug enabled
            {
                "type": VulnerabilityType.DEBUG_ENABLED,
                "severity": VulnerabilitySeverity.LOW,
                "pattern": re.compile(r"debug\s*=\s*True", re.IGNORECASE),
                "description": "Debug mode enabled in production",
                "recommendation": "Disable debug mode in production environments",
                "cwe_id": "CWE-489",
            },
            # Eval usage
            {
                "type": VulnerabilityType.EVAL_USAGE,
                "severity": VulnerabilitySeverity.MEDIUM,
                "pattern": re.compile(r"\beval\s*\(", re.IGNORECASE),
                "description": "Use of eval() function",
                "recommendation": "Avoid eval() with untrusted input, use safer alternatives",
                "cwe_id": "CWE-95",
            },
        ]

        return rules

    async def scan_path(self, path: Union[str, Path], **kwargs) -> ScanReport:
        """Scan a path for security vulnerabilities."""
        start_time = asyncio.get_event_loop().time()

        try:
            path_obj = Path(path)
            if not path_obj.exists():
                raise FileNotFoundError(f"Path does not exist: {path}")

            vulnerabilities = []
            if path_obj.is_file():
                vulnerabilities.extend(await self._scan_file(path_obj))
            else:
                vulnerabilities.extend(await self._scan_directory(path_obj))

            # Filter by severity threshold and confidence
            severity_order = {sev.value: i for i, sev in enumerate(VulnerabilitySeverity)}
            threshold_level = severity_order.get(self.config.severity_threshold, 0)

            filtered_vulns = [
                v
                for v in vulnerabilities
                if (
                    severity_order.get(v.severity.value, 0) >= threshold_level
                    and v.confidence >= self.config.min_confidence
                )
            ]

            scan_time = (asyncio.get_event_loop().time() - start_time) * 1000

            # Create summary
            severity_counts = {}
            for vuln in filtered_vulns:
                severity_counts[vuln.severity.value] = severity_counts.get(vuln.severity.value, 0) + 1

            return await self._create_report(
                filtered_vulns,
                scan_time,
                metadata={
                    "total_vulnerabilities": len(vulnerabilities),
                    "filtered_vulnerabilities": len(filtered_vulns),
                    "severity_breakdown": severity_counts,
                },
            )

        except Exception as e:
            self.logger.error(f"Error scanning path {path}: {e}")
            scan_time = (asyncio.get_event_loop().time() - start_time) * 1000
            return await self._create_report([], scan_time, ScanResult.FAILURE, {"error": str(e)})

    async def scan_content(self, content: str, filename: Optional[str] = None, **kwargs) -> List[Vulnerability]:
        """Scan content string for vulnerabilities."""
        vulnerabilities = []

        for rule in self._rules:
            matches = rule["pattern"].findall(content)
            if matches:
                # Find line numbers for matches
                lines = content.splitlines()
                for match in matches:
                    for line_no, line in enumerate(lines, 1):
                        if match in line:
                            # Extract code snippet
                            start_line = max(1, line_no - 2)
                            end_line = min(len(lines), line_no + 2)
                            code_snippet = "\n".join(lines[start_line - 1 : end_line])

                            vulnerabilities.append(
                                Vulnerability(
                                    file_path=filename or "<content>",
                                    line_number=line_no,
                                    vulnerability_type=rule["type"],
                                    severity=rule["severity"],
                                    description=rule["description"],
                                    code_snippet=code_snippet,
                                    recommendation=rule["recommendation"],
                                    confidence=self._calculate_confidence(match, rule),
                                    cwe_id=rule.get("cwe_id"),
                                )
                            )
                            break  # Only report first occurrence per match

        return vulnerabilities

    async def _scan_file(self, file_path: Path) -> List[Vulnerability]:
        """Scan a single file for vulnerabilities."""
        if not self.should_scan_file(file_path):
            return []

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            return await self.scan_content(content, str(file_path))
        except (OSError, UnicodeDecodeError) as e:
            self.logger.warning(f"Could not read file {file_path}: {e}")
            return []

    async def _scan_directory(self, dir_path: Path) -> List[Vulnerability]:
        """Scan a directory recursively for vulnerabilities."""
        vulnerabilities = []
        semaphore = asyncio.Semaphore(5)  # Limit concurrent file reads

        async def scan_file_async(file_path: Path):
            async with semaphore:
                return await self._scan_file(file_path)

        # Find all files to scan
        files_to_scan = []
        for root, dirs, files in os.walk(dir_path):
            # Skip excluded directories
            dirs[:] = [
                d for d in dirs if not any(excl in os.path.join(root, d) for excl in self.config.exclude_patterns)
            ]

            for file in files:
                file_path = Path(root) / file
                if self._is_code_file(file_path):
                    files_to_scan.append(file_path)

        # Scan files concurrently
        if files_to_scan:
            tasks = [scan_file_async(fp) for fp in files_to_scan[:500]]  # Limit to 500 files
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, list):
                    vulnerabilities.extend(result)
                elif isinstance(result, Exception):
                    self.logger.warning(f"Error scanning file: {result}")

        return vulnerabilities

    def _calculate_confidence(self, match: str, rule: Dict[str, Any]) -> float:
        """Calculate confidence score for a vulnerability finding."""
        confidence = 0.8  # Base confidence

        # Adjust based on rule type
        if rule["type"] in [VulnerabilityType.SQL_INJECTION, VulnerabilityType.COMMAND_INJECTION]:
            confidence += 0.1  # These are more reliable patterns

        # Reduce confidence for generic patterns
        if "potential" in rule["description"].lower():
            confidence -= 0.1

        # Reduce confidence for very short matches
        if len(match) < 10:
            confidence -= 0.2

        return max(0.0, min(1.0, confidence))

    def _is_code_file(self, file_path: Path) -> bool:
        """Check if a file is a code file that should be scanned."""
        code_extensions = {
            ".py",
            ".js",
            ".ts",
            ".java",
            ".c",
            ".cpp",
            ".h",
            ".hpp",
            ".cs",
            ".php",
            ".rb",
            ".go",
            ".rs",
            ".swift",
            ".kt",
            ".scala",
            ".clj",
            ".hs",
            ".ml",
            ".fs",
            ".vb",
            ".pl",
            ".tcl",
            ".lua",
            ".r",
            ".sh",
            ".bash",
            ".zsh",
            ".ps1",
        }

        return file_path.suffix.lower() in code_extensions
