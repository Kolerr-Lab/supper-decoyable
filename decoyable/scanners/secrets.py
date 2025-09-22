import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Pattern, Tuple

"""
decoyable.scanners.secrets

Simple, extensible secret scanner for discovering likely secrets in text files.
Designed to be light-weight and integrate into the decoyable project scanners package.

Usage:

    findings = scan_file("path/to/file.py")
    for f in findings:
        print(f)
"""


@dataclass(frozen=True)
class SecretFinding:
    filename: Optional[str]
    lineno: int
    secret_type: str
    match: str
    context: str

    def masked(self, keep_left: int = 4, keep_right: int = 4, mask_char: str = "*") -> str:
        s = self.match
        if len(s) <= keep_left + keep_right:
            return mask_char * len(s)
        return s[:keep_left] + (mask_char * (len(s) - keep_left - keep_right)) + s[-keep_right:]


# Patterns tuned to reduce false positives but intentionally permissive.
_DEFAULT_PATTERNS: List[Tuple[str, Pattern]] = [
    # AWS Access Key ID
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    # AWS Secret Access Key (40 base64-ish chars)
    ("AWS Secret Access Key", re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")),
    # Google API key
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    # GitHub personal access token (classic and new prefixes)
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36}\b")),
    ("GitHub Token (legacy)", re.compile(r"\bgh[0-9a-zA-Z]{36}\b")),
    # Generic OAuth / bearer tokens common prefixes
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,48}\b")),
    ("Generic Bearer/JWT-like", re.compile(r"\b[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{8,}\b")),
    # Private key blocks
    ("Private Key", re.compile(r"-----BEGIN (?:RSA|OPENSSH|EC|DSA|PRIVATE) KEY-----")),
    # Basic API token patterns (prefixes)
    ("Stripe Key", re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b")),
    ("Twilio API Key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    # Generic assignment like password = "..."
    ("Password Assignment", re.compile(r"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*['\"]?([^'\"\s]{6,128})['\"]?")),
    # Generic high-entropy-looking strings (heuristic): long base64-like tokens
    ("High-Entropy String", re.compile(r"\b[A-Za-z0-9\-_]{32,}\b")),
]


def _is_binary(bytestr: bytes) -> bool:
    # Simple heuristic: null byte presence or many non-text bytes
    if b"\x00" in bytestr:
        return True
    text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)))
    nontext = sum(1 for b in bytestr if b not in text_chars)
    return (nontext / max(1, len(bytestr))) > 0.30


def scan_text(
    text: str,
    filename: Optional[str] = None,
    patterns: Optional[Iterable[Tuple[str, Pattern]]] = None,
    allowlist: Optional[Iterable[Pattern]] = None,
) -> List[SecretFinding]:
    """
    Scan a text string and return a list of SecretFinding objects.
    - patterns: iterable of (name, compiled_regex). If None, uses default patterns.
    - allowlist: iterable of compiled regexes; matches that match any allowlist pattern are ignored.
    """
    if patterns is None:
        patterns = _DEFAULT_PATTERNS
    allowlist = list(allowlist or [])

    findings: List[SecretFinding] = []
    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for name, regex in patterns:
            for m in regex.finditer(line):
                matched = m.group(0)
                # If allowlist contains a pattern that matches the matched string, skip it
                if any(a.search(matched) for a in allowlist):
                    continue
                # avoid trivial short matches
                if len(matched) < 6:
                    continue
                # Build context: include a slice of the line around the match
                ctx = line.strip()
                findings.append(
                    SecretFinding(
                        filename=filename,
                        lineno=lineno,
                        secret_type=name,
                        match=matched,
                        context=ctx,
                    )
                )
    # deduplicate by (filename, lineno, type, match)
    unique = {}
    for f in findings:
        key = (f.filename, f.lineno, f.secret_type, f.match)
        unique[key] = f
    return sorted(unique.values(), key=lambda x: (x.filename or "", x.lineno))


def scan_file(
    filepath: str,
    patterns: Optional[Iterable[Tuple[str, Pattern]]] = None,
    allowlist: Optional[Iterable[Pattern]] = None,
    max_bytes: int = 5_000_000,
) -> List[SecretFinding]:
    """
    Read and scan a file path. Binary files are skipped.
    - max_bytes: don't read files larger than this (to avoid huge binary files)
    """
    p = Path(filepath)
    if not p.is_file():
        return []

    try:
        raw = p.read_bytes()
    except Exception:
        return []

    if len(raw) > max_bytes:
        # don't process very large files
        return []

    if _is_binary(raw):
        return []

    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        text = raw.decode(errors="replace")

    return scan_text(text, filename=str(p), patterns=patterns, allowlist=allowlist)


# Convenience entry for scanning many files
def scan_paths(
    paths: Iterable[str],
    patterns: Optional[Iterable[Tuple[str, Pattern]]] = None,
    allowlist: Optional[Iterable[Pattern]] = None,
) -> List[SecretFinding]:
    results: List[SecretFinding] = []
    for p in paths:
        results.extend(scan_file(p, patterns=patterns, allowlist=allowlist))
    return sorted(results, key=lambda x: (x.filename or "", x.lineno))


# Small demonstration utility when executed as a script (keeps module self-contained).
if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python -m decoyable.scanners.secrets <file1> [file2 ...]")
        raise SystemExit(1)

    files = sys.argv[1:]
    findings = scan_paths(files)
    for f in findings:
        print(f"{f.filename}:{f.lineno} [{f.secret_type}] {f.masked()}  // {f.context}")


class SecretScanner:
    """
    Class-based interface for secret scanning.
    Provides a more object-oriented API for the secret scanning functionality.
    """

    def __init__(self):
        self.patterns = _DEFAULT_PATTERNS
        self.allowlist = []

    def scan_content(self, content: str, filename: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Scan content for secrets.

        Args:
            content: Text content to scan
            filename: Optional filename for context

        Returns:
            List of findings as dictionaries
        """
        findings = scan_text(content, filename=filename, patterns=self.patterns, allowlist=self.allowlist)
        return [
            {
                "filename": f.filename,
                "lineno": f.lineno,
                "secret_type": f.secret_type,
                "match": f.match,
                "context": f.context,
                "masked": f.masked()
            }
            for f in findings
        ]

    def scan_file(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Scan a file for secrets.

        Args:
            filepath: Path to the file to scan

        Returns:
            List of findings as dictionaries
        """
        findings = scan_file(filepath, patterns=self.patterns, allowlist=self.allowlist)
        return [
            {
                "filename": f.filename,
                "lineno": f.lineno,
                "secret_type": f.secret_type,
                "match": f.match,
                "context": f.context,
                "masked": f.masked()
            }
            for f in findings
        ]
