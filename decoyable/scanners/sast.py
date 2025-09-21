"""Static Application Security Testing (SAST) scanner for DECOYABLE."""

import re
import ast
import os
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum


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


class SASTScanner:
    """Static Application Security Testing scanner."""

    def __init__(self):
        """Initialize the SAST scanner with vulnerability patterns."""
        self.vulnerability_patterns = self._load_patterns()

    def _load_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load vulnerability detection patterns."""
        return {
            # SQL Injection patterns
            "sql_injection": {
                "patterns": [
                    r"execute\s*\(\s*.*\+.*\)",
                    r"cursor\.execute\s*\(\s*.*\%.*\)",
                    r"SELECT.*WHERE.*\+",
                    r"INSERT.*VALUES.*\+",
                    r"UPDATE.*SET.*\+",
                ],
                "type": VulnerabilityType.SQL_INJECTION,
                "severity": VulnerabilitySeverity.HIGH,
                "description": "Potential SQL injection vulnerability",
                "recommendation": "Use parameterized queries or prepared statements"
            },

            # XSS patterns
            "xss": {
                "patterns": [
                    r"innerHTML\s*\+=",
                    r"outerHTML\s*\+=",
                    r"document\.write\s*\(",
                    r"eval\s*\(",
                ],
                "type": VulnerabilityType.XSS,
                "severity": VulnerabilitySeverity.HIGH,
                "description": "Potential Cross-Site Scripting (XSS) vulnerability",
                "recommendation": "Use proper output encoding and Content Security Policy"
            },

            # Command injection patterns
            "command_injection": {
                "patterns": [
                    r"os\.system\s*\(",
                    r"subprocess\.call\s*\(",
                    r"subprocess\.run\s*\(",
                    r"os\.popen\s*\(",
                    r"exec\s*\(",
                ],
                "type": VulnerabilityType.COMMAND_INJECTION,
                "severity": VulnerabilitySeverity.CRITICAL,
                "description": "Potential command injection vulnerability",
                "recommendation": "Validate and sanitize user input, use safe APIs"
            },

            # Path traversal patterns
            "path_traversal": {
                "patterns": [
                    r"\.\./",
                    r"\.\.\\",
                    r"open\s*\(\s*.*\+.*\)",
                    r"Path\s*\(\s*.*\+.*\)",
                ],
                "type": VulnerabilityType.PATH_TRAVERSAL,
                "severity": VulnerabilitySeverity.HIGH,
                "description": "Potential path traversal vulnerability",
                "recommendation": "Validate paths and use safe path joining functions"
            },

            # Insecure random patterns
            "insecure_random": {
                "patterns": [
                    r"random\.random\(\)",
                    r"random\.randint\(",
                    r"random\.choice\(",
                ],
                "type": VulnerabilityType.INSECURE_RANDOM,
                "severity": VulnerabilitySeverity.MEDIUM,
                "description": "Use of insecure random number generation",
                "recommendation": "Use secrets module for cryptographic purposes"
            },

            # Hardcoded secrets patterns
            "hardcoded_secrets": {
                "patterns": [
                    r"password\s*=\s*['\"][^'\"]*['\"]",
                    r"secret\s*=\s*['\"][^'\"]*['\"]",
                    r"token\s*=\s*['\"][^'\"]*['\"]",
                    r"key\s*=\s*['\"][^'\"]*['\"]",
                    r"api_key\s*=\s*['\"][^'\"]*['\"]",
                ],
                "type": VulnerabilityType.HARDCODED_SECRET,
                "severity": VulnerabilitySeverity.HIGH,
                "description": "Potential hardcoded secret or credential",
                "recommendation": "Use environment variables or secure credential storage"
            },

            # Weak cryptography patterns
            "weak_crypto": {
                "patterns": [
                    r"md5\s*\(",
                    r"sha1\s*\(",
                    r"DES\s*\(",
                    r"RC4\s*\(",
                ],
                "type": VulnerabilityType.WEAK_CRYPTO,
                "severity": VulnerabilitySeverity.MEDIUM,
                "description": "Use of weak or deprecated cryptographic functions",
                "recommendation": "Use modern cryptographic algorithms like SHA-256, AES"
            },

            # Deserialization patterns
            "deserialization": {
                "patterns": [
                    r"pickle\.loads?\s*\(",
                    r"yaml\.load\s*\(",
                    r"json\.loads?\s*\(",
                ],
                "type": VulnerabilityType.DESERIALIZATION,
                "severity": VulnerabilitySeverity.HIGH,
                "description": "Potential unsafe deserialization vulnerability",
                "recommendation": "Validate input and use safe deserialization methods"
            },

            # SSRF patterns
            "ssrf": {
                "patterns": [
                    r"requests\.get\s*\(\s*.*\+.*\)",
                    r"urllib\.request\.urlopen\s*\(",
                    r"urllib2\.urlopen\s*\(",
                ],
                "type": VulnerabilityType.SSRF,
                "severity": VulnerabilitySeverity.HIGH,
                "description": "Potential Server-Side Request Forgery (SSRF) vulnerability",
                "recommendation": "Validate and whitelist URLs, use proper input validation"
            },

            # XXE patterns
            "xxe": {
                "patterns": [
                    r"xml\.etree\.ElementTree\.parse\s*\(",
                    r"xml\.sax\.parse\s*\(",
                    r"xml\.dom\.minidom\.parse\s*\(",
                ],
                "type": VulnerabilityType.XXE,
                "severity": VulnerabilitySeverity.MEDIUM,
                "description": "Potential XML External Entity (XXE) vulnerability",
                "recommendation": "Disable external entity processing in XML parsers"
            }
        }

    def scan_file(self, file_path: str) -> List[Vulnerability]:
        """Scan a single file for vulnerabilities."""
        vulnerabilities = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

                for line_num, line in enumerate(lines, 1):
                    for vuln_name, vuln_config in self.vulnerability_patterns.items():
                        for pattern in vuln_config["patterns"]:
                            if re.search(pattern, line, re.IGNORECASE):
                                # Get code snippet (current line +/- 2 lines)
                                start_line = max(0, line_num - 3)
                                end_line = min(len(lines), line_num + 2)
                                snippet_lines = lines[start_line:end_line]
                                snippet = '\n'.join(f"{i+start_line+1:4d}: {line}" for i, line in enumerate(snippet_lines))

                                vulnerability = Vulnerability(
                                    file_path=file_path,
                                    line_number=line_num,
                                    vulnerability_type=vuln_config["type"],
                                    severity=vuln_config["severity"],
                                    description=vuln_config["description"],
                                    code_snippet=snippet,
                                    recommendation=vuln_config["recommendation"]
                                )
                                vulnerabilities.append(vulnerability)
                                break  # Only report once per line per vulnerability type

        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")

        return vulnerabilities

    def scan_directory(self, directory_path: str, extensions: Optional[List[str]] = None) -> List[Vulnerability]:
        """Scan a directory recursively for vulnerabilities."""
        if extensions is None:
            extensions = ['.py', '.js', '.ts', '.java', '.php', '.rb', '.go', '.rs']

        vulnerabilities = []
        directory = Path(directory_path)

        for file_path in directory.rglob('*'):
            if file_path.is_file() and file_path.suffix.lower() in extensions:
                file_vulnerabilities = self.scan_file(str(file_path))
                vulnerabilities.extend(file_vulnerabilities)

        return vulnerabilities

    def scan_code_string(self, code: str, file_path: str = "<string>") -> List[Vulnerability]:
        """Scan a code string for vulnerabilities."""
        vulnerabilities = []
        lines = code.split('\n')

        for line_num, line in enumerate(lines, 1):
            for vuln_name, vuln_config in self.vulnerability_patterns.items():
                for pattern in vuln_config["patterns"]:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Get code snippet
                        start_line = max(0, line_num - 3)
                        end_line = min(len(lines), line_num + 2)
                        snippet_lines = lines[start_line:end_line]
                        snippet = '\n'.join(f"{i+start_line+1:4d}: {line}" for i, line in enumerate(snippet_lines))

                        vulnerability = Vulnerability(
                            file_path=file_path,
                            line_number=line_num,
                            vulnerability_type=vuln_config["type"],
                            severity=vuln_config["severity"],
                            description=vuln_config["description"],
                            code_snippet=snippet,
                            recommendation=vuln_config["recommendation"]
                        )
                        vulnerabilities.append(vulnerability)
                        break

        return vulnerabilities


def scan_sast(path: str) -> Dict[str, Any]:
    """Main function to perform SAST scanning on a path."""
    scanner = SASTScanner()

    if os.path.isfile(path):
        vulnerabilities = scanner.scan_file(path)
    elif os.path.isdir(path):
        vulnerabilities = scanner.scan_directory(path)
    else:
        raise ValueError(f"Path {path} is neither a file nor directory")

    # Group vulnerabilities by severity
    severity_counts = {}
    for vuln in vulnerabilities:
        severity_counts[vuln.severity.value] = severity_counts.get(vuln.severity.value, 0) + 1

    return {
        "vulnerabilities": [vars(vuln) for vuln in vulnerabilities],
        "summary": {
            "total_vulnerabilities": len(vulnerabilities),
            "severity_breakdown": severity_counts,
            "files_scanned": len(set(v.file_path for v in vulnerabilities)) if vulnerabilities else 0
        }
    }