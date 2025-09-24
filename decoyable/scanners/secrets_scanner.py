"""
Secrets scanner implementation with dependency injection support.
"""

import asyncio
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Tuple, Union

from decoyable.core.logging import get_logger
from decoyable.scanners.interfaces import BaseScanner, ScannerConfig, ScannerType, ScanReport, ScanResult


@dataclass(frozen=True)
class SecretFinding:
    """Represents a potential secret found in code."""

    filename: Optional[str]
    lineno: int
    secret_type: str
    match: str
    context: str
    confidence: float = 1.0
    is_issue: bool = True

    def masked(self, keep_left: int = 4, keep_right: int = 4, mask_char: str = "*") -> str:
        """Return masked version of the secret."""
        s = self.match
        if len(s) <= keep_left + keep_right:
            return mask_char * len(s)
        return s[:keep_left] + (mask_char * (len(s) - keep_left - keep_right)) + s[-keep_right:]


@dataclass
class SecretsScannerConfig:
    """Configuration for the secrets scanner."""

    enabled: bool = True
    timeout_seconds: int = 300
    max_file_size_mb: int = 10
    exclude_patterns: List[str] = None
    min_confidence: float = 0.8
    custom_patterns: Optional[Dict[str, str]] = None

    def __post_init__(self):
        if self.exclude_patterns is None:
            self.exclude_patterns = [".git", "__pycache__", "node_modules", ".venv", "venv"]


class SecretsScanner(BaseScanner):
    """Advanced secrets scanner with pattern matching and false positive reduction."""

    # Default patterns for common secrets
    DEFAULT_PATTERNS: List[Tuple[str, Pattern[str]]] = [
        # AWS Access Key ID
        ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        # AWS Secret Access Key (40 base64-ish chars)
        ("AWS Secret Access Key", re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")),
        # Google API key
        ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
        # GitHub personal access token
        ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36}\b")),
        ("GitHub Token (legacy)", re.compile(r"\bgh[0-9a-zA-Z]{36}\b")),
        # Slack tokens
        ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,48}\b")),
        # Generic JWT tokens
        ("JWT Token", re.compile(r"\b[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{8,}\b")),
        # Private key headers
        ("Private Key", re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----", re.IGNORECASE)),
        # Generic high-entropy strings (potential API keys)
        ("High Entropy String", re.compile(r"\b[A-Za-z0-9+/]{32,}\b")),
    ]

    def __init__(self, config: SecretsScannerConfig):
        super().__init__(ScannerType.SECRETS, config)
        self.config: SecretsScannerConfig = config
        self._patterns = self._compile_patterns()

    def _compile_patterns(self) -> List[Tuple[str, Pattern[str]]]:
        """Compile regex patterns for secret detection."""
        patterns = self.DEFAULT_PATTERNS.copy()

        # Add custom patterns if provided
        if self.config.custom_patterns:
            for name, pattern_str in self.config.custom_patterns.items():
                try:
                    pattern = re.compile(pattern_str)
                    patterns.append((name, pattern))
                except re.error as e:
                    self.logger.warning(f"Invalid custom pattern '{name}': {e}")

        return patterns

    async def scan_path(self, path: Union[str, Path], **kwargs) -> ScanReport:
        """Scan a path for secrets."""
        start_time = asyncio.get_event_loop().time()

        try:
            path_obj = Path(path)
            if not path_obj.exists():
                raise FileNotFoundError(f"Path does not exist: {path}")

            findings = []
            if path_obj.is_file():
                findings.extend(await self._scan_file(path_obj))
            else:
                findings.extend(await self._scan_directory(path_obj))

            scan_time = (asyncio.get_event_loop().time() - start_time) * 1000

            # Filter by confidence
            filtered_findings = [f for f in findings if f.confidence >= self.config.min_confidence]

            return await self._create_report(
                filtered_findings,
                scan_time,
                metadata={"total_findings": len(findings), "filtered_findings": len(filtered_findings)},
            )

        except Exception as e:
            self.logger.error(f"Error scanning path {path}: {e}")
            scan_time = (asyncio.get_event_loop().time() - start_time) * 1000
            return await self._create_report([], scan_time, ScanResult.FAILURE, {"error": str(e)})

    async def scan_content(self, content: str, filename: Optional[str] = None, **kwargs) -> List[SecretFinding]:
        """Scan content string for secrets."""
        findings = []

        for line_no, line in enumerate(content.splitlines(), 1):
            line_findings = self._scan_line(line, filename or "<content>", line_no)
            findings.extend(line_findings)

        # Filter by confidence
        return [f for f in findings if f.confidence >= self.config.min_confidence]

    async def _scan_file(self, file_path: Path) -> List[SecretFinding]:
        """Scan a single file for secrets."""
        if not self.should_scan_file(file_path):
            return []

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            return await self.scan_content(content, str(file_path))
        except (OSError, UnicodeDecodeError) as e:
            self.logger.warning(f"Could not read file {file_path}: {e}")
            return []

    async def _scan_directory(self, dir_path: Path) -> List[SecretFinding]:
        """Scan a directory recursively for secrets."""
        findings = []
        semaphore = asyncio.Semaphore(10)  # Limit concurrent file reads

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
                if self._is_text_file(file_path):
                    files_to_scan.append(file_path)

        # Scan files concurrently
        if files_to_scan:
            tasks = [scan_file_async(fp) for fp in files_to_scan[:1000]]  # Limit to 1000 files
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, list):
                    findings.extend(result)
                elif isinstance(result, Exception):
                    self.logger.warning(f"Error scanning file: {result}")

        return findings

    def _scan_line(self, line: str, filename: str, line_no: int) -> List[SecretFinding]:
        """Scan a single line for secrets."""
        findings = []

        for secret_type, pattern in self._patterns:
            matches = pattern.findall(line)
            for match in matches:
                # Calculate confidence based on pattern and context
                confidence = self._calculate_confidence(match, secret_type, line)

                # Extract context (surrounding characters)
                context = line.strip()
                if len(context) > 100:
                    # Find match position and extract context around it
                    match_start = line.find(match)
                    start = max(0, match_start - 50)
                    end = min(len(line), match_start + len(match) + 50)
                    context = "..." + line[start:end] + "..."

                findings.append(
                    SecretFinding(
                        filename=filename,
                        lineno=line_no,
                        secret_type=secret_type,
                        match=match,
                        context=context,
                        confidence=confidence,
                    )
                )

        return findings

    def _calculate_confidence(self, match: str, secret_type: str, line: str) -> float:
        """Calculate confidence score for a potential secret."""
        confidence = 0.5  # Base confidence

        # Boost confidence for known patterns
        if secret_type in ["AWS Access Key ID", "AWS Secret Access Key", "GitHub Token"]:
            confidence += 0.3

        # Reduce confidence if in comments or test files
        if any(comment in line.lower() for comment in ["# todo", "# fixme", "# hack", "test", "example"]):
            confidence -= 0.2

        # Reduce confidence for very short matches
        if len(match) < 10:
            confidence -= 0.2

        # Boost confidence for high entropy
        if self._calculate_entropy(match) > 4.5:
            confidence += 0.2

        return max(0.0, min(1.0, confidence))

    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string."""
        import math
        from collections import Counter

        if not s:
            return 0.0

        entropy = 0.0
        length = len(s)
        counts = Counter(s)

        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def _is_text_file(self, file_path: Path) -> bool:
        """Check if a file is likely a text file."""
        text_extensions = {
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
            ".fish",
            ".ps1",
            ".sql",
            ".xml",
            ".json",
            ".yaml",
            ".yml",
            ".toml",
            ".ini",
            ".cfg",
            ".conf",
            ".env",
            ".md",
            ".txt",
            ".rst",
            ".adoc",
        }

        return file_path.suffix.lower() in text_extensions or file_path.name in {
            "Dockerfile",
            "Makefile",
            "CMakeLists.txt",
            "requirements.txt",
            "setup.py",
            "pyproject.toml",
        }


# Import os here to avoid circular imports
import os
