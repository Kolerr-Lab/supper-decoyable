"""
decoyable/defense/analysis.py

LLM-powered attack analysis and adaptive defense for DECOYABLE.
Classifies attacks, provides recommendations, and adapts defenses dynamically.
"""

import json
import logging
import os
import re
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter
from pydantic import BaseModel

# Configure logging
logger = logging.getLogger(__name__)

# Environment variables
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
KNOWLEDGE_DB_PATH = os.getenv("KNOWLEDGE_DB_PATH", "decoyable_knowledge.db")

# Attack classification patterns (improved specificity)
ATTACK_PATTERNS = {
    "sqli": [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|UNION)\b.*\b(FROM|INTO|TABLE|WHERE|ALL)\b)",
        r"(\bUNION\b.*\bSELECT\b)",
        r"(\bOR\b.*['\"]\s*\d+\s*=\s*\d+\s*['\"])",
        r"(\bAND\b.*['\"]\s*\d+\s*=\s*\d+\s*['\"])",
        r"(\%27|\%22|%3B)",  # URL encoded quotes and semicolons
        r"(\blike\b.*\%.*\%|\blike\b.*\_.*\_)",  # LIKE with wildcards
        r"(1=1|1=0|\d+=\d+.*--|'\d+'\s*=\s*'\d+')",  # Common SQL injection payloads
        r"(\bor\b.*\d+\s*=\s*\d+)",  # OR 1=1 patterns
        r"OR.*=.*",  # Simple OR = pattern
    ],
    "xss": [
        r"(<script[^>]*>.*?</script>)",
        r"(<iframe[^>]*>.*?</iframe>)",
        r"(javascript:)",
        r"(vbscript:)",
        r"(on\w+\s*=.*[<>\"'])",
        r"(<img[^>]*onerror[^>]*=)",
        r"(<svg[^>]*onload[^>]*=)",
        r"(eval\(|document\.|window\.)",
    ],
    "command_injection": [
        r"(\|\s*\w+|\&\s*\w+|;\s*\w+)",  # Command chaining
        r"(\$\([^)]+\)|\`[^`]+\`)",  # Command substitution
        r"(\b(cat|ls|pwd|whoami|id|ps|netstat|wget|curl|nc|bash|sh|python|perl)\b.*\|)",
        r"(\b(rm|del|format|shutdown|reboot|halt)\b.*[;&|])",
        r"(\$\{[^}]+\})",  # Variable expansion
    ],
    "path_traversal": [
        r"(\.\./|\.\.\\){2,}",  # Multiple directory traversals
        r"(\.\./\.\./)",
        r"(%2e%2e%2f|%2e%2e%5c){2,}",  # URL encoded
        r"(etc/passwd|etc/shadow|boot.ini|web.config)",  # Common target files
        r"(\.\./.*\.\./.*\.\./)",  # Complex traversals
    ],
    "brute_force": [
        r"(\badmin\b.*\bpassword\b|\broot\b.*\bpassword\b)",  # Specific credential attempts
        r"(\blogin\b.*\bfailed\b|\bauth\b.*\bfailed\b)",  # Failed login patterns
        r"(\buser\b.*\bpass\b.*\battempt\b)",  # Brute force attempt patterns
    ],
    "reconnaissance": [
        r"(\b(nmap|nikto|dirbuster|sqlmap|metasploit|nessus|acunetix|burpsuite|owasp|qualys)\b)",
        r"(User-Agent:.*(scanner|bot|crawler|spider|dirbuster|gobuster|acunetix|qualys|nessus))",
        r"(\.php|\.asp|\.jsp|\.bak|\.old|\.txt|\.sql|\.env|\.git|\.svn|\.DS_Store|\.htaccess|\.htpasswd)",
        r"(\badminer\b|\bphpmyadmin\b|\bwebmin\b|\bcpanel\b|\bplesk\b|\bwhm\b)",
        r"(\?C=|\?N=|\?O=|\?S=|index\.php\?page=|script\.php\?id=)",  # Directory listing attempts
        r"(\b/etc/passwd\b|\b/etc/shadow\b|\b/proc/version\b|\b/proc/cpuinfo\b)",  # System file access
    ],
}


class AttackAnalysis(BaseModel):
    """Model for LLM analysis results."""

    attack_type: str
    confidence: float
    recommended_action: str
    explanation: str
    severity: str
    indicators: List[str] = []


class KnowledgeEntry(BaseModel):
    """Model for knowledge base entries."""

    id: Optional[int] = None
    timestamp: str
    attack_data: Dict[str, Any]
    analysis_result: Dict[str, Any]
    feedback: Optional[str] = None


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


class KnowledgeBase:
    """SQLite-based knowledge base for attack analysis and learning."""

    def __init__(self, db_path: str = KNOWLEDGE_DB_PATH):
        self.db_path = Path(db_path)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS attacks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    attack_data TEXT NOT NULL,
                    analysis_result TEXT NOT NULL,
                    feedback TEXT,
                    created_at REAL
                )
            """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_timestamp ON attacks(timestamp)
            """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_attack_type ON attacks(
                    json_extract(analysis_result, '$.attack_type')
                )
            """
            )

    def store_analysis(self, attack_data: Dict[str, Any], analysis_result: Dict[str, Any]) -> int:
        """Store attack analysis in knowledge base."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                INSERT INTO attacks (timestamp, attack_data, analysis_result, created_at)
                VALUES (?, ?, ?, ?)
            """,
                (
                    attack_data.get("timestamp", datetime.utcnow().isoformat()),
                    json.dumps(attack_data),
                    json.dumps(analysis_result),
                    datetime.utcnow().timestamp(),
                ),
            )
            return cursor.lastrowid

    def get_recent_analyses(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent attack analyses."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                SELECT id, timestamp, attack_data, analysis_result, feedback
                FROM attacks
                ORDER BY created_at DESC
                LIMIT ?
            """,
                (limit,),
            )

            results = []
            for row in cursor.fetchall():
                attack_id, timestamp, attack_data, analysis_result, feedback = row
                results.append(
                    {
                        "id": attack_id,
                        "timestamp": timestamp,
                        "attack_data": json.loads(attack_data),
                        "analysis_result": json.loads(analysis_result),
                        "feedback": feedback,
                    }
                )
            return results

    def get_attack_stats(self, days: int = 7) -> Dict[str, Any]:
        """Get attack statistics for the last N days."""
        since_timestamp = (datetime.utcnow() - timedelta(days=days)).timestamp()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                SELECT
                    json_extract(analysis_result, '$.attack_type') as attack_type,
                    COUNT(*) as count
                FROM attacks
                WHERE created_at >= ?
                GROUP BY attack_type
                ORDER BY count DESC
            """,
                (since_timestamp,),
            )

            stats = {"total_attacks": 0, "attack_types": {}}
            for row in cursor.fetchall():
                attack_type, count = row
                stats["attack_types"][attack_type or "unknown"] = count
                stats["total_attacks"] += count

            return stats

    def update_feedback(self, attack_id: int, feedback: str) -> bool:
        """Update feedback for an attack analysis."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                UPDATE attacks SET feedback = ? WHERE id = ?
            """,
                (feedback, attack_id),
            )
            return cursor.rowcount > 0


# Global knowledge base instance
knowledge_base = KnowledgeBase()


async def analyze_attack_with_llm(attack_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze attack using OpenAI LLM.

    Args:
        attack_data: Attack log data

    Returns:
        Analysis result with attack_type, confidence, recommended_action
    """
    if not OPENAI_API_KEY:
        # Fallback to pattern-based analysis
        return await analyze_attack_patterns(attack_data)

    try:
        prompt = f"""
Analyze this HTTP request for potential cyber attack patterns. Respond with JSON only.

Request Details:
- Method: {attack_data.get('method', 'UNKNOWN')}
- Path: {attack_data.get('path', 'UNKNOWN')}
- Headers: {json.dumps(attack_data.get('headers', {}), indent=2)}
- Body: {attack_data.get('body', 'None')[:500]}...
- Query Params: {json.dumps(attack_data.get('query_params', {}), indent=2)}
- User Agent: {attack_data.get('user_agent', 'None')}

Classify the attack type and provide:
1. attack_type: (SQLi, XSS, command_injection, path_traversal, brute_force, reconnaissance, unknown)
2. confidence: (0.0-1.0)
3. recommended_action: (block_ip, monitor, log_only, ignore)
4. explanation: brief explanation
5. severity: (critical, high, medium, low, info)
6. indicators: list of suspicious patterns found

JSON Response:
"""

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {OPENAI_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "gpt-3.5-turbo",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 500,
                    "temperature": 0.1,
                },
            )

            if response.status_code == 200:
                result = response.json()
                content = result["choices"][0]["message"]["content"]

                # Parse JSON response
                try:
                    analysis = json.loads(content)
                    return analysis
                except json.JSONDecodeError:
                    logger.error(f"Failed to parse LLM response: {content}")
                    return await analyze_attack_patterns(attack_data)
            else:
                logger.error(f"OpenAI API error: {response.status_code} - {response.text}")
                return await analyze_attack_patterns(attack_data)

    except Exception as exc:
        logger.error(f"LLM analysis failed: {exc}")
        return await analyze_attack_patterns(attack_data)


async def analyze_attack_patterns(attack_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Fallback pattern-based attack analysis.

    Args:
        attack_data: Attack log data

    Returns:
        Analysis result
    """
    # Combine all text for analysis
    text_to_analyze = ""
    text_to_analyze += attack_data.get("path", "")
    text_to_analyze += " " + json.dumps(attack_data.get("headers", {}))
    text_to_analyze += " " + str(attack_data.get("body", ""))
    text_to_analyze += " " + json.dumps(attack_data.get("query_params", {}))

    # Check against patterns with prioritization
    all_patterns = adaptive_defense.get_all_patterns()

    # Priority order: most dangerous to least dangerous
    priority_order = [
        "sqli",
        "command_injection",
        "xss",
        "path_traversal",
        "brute_force",
        "reconnaissance",
    ]

    matches = {}
    max_confidence = 0.0
    best_attack_type = "unknown"
    best_indicators = []

    for attack_type in priority_order:
        if attack_type not in all_patterns:
            continue

        patterns = all_patterns[attack_type]
        matches[attack_type] = []

        for pattern in patterns:
            try:
                if re.search(pattern, text_to_analyze, re.IGNORECASE | re.MULTILINE):
                    matches[attack_type].append(pattern)
            except re.error:
                continue  # Skip invalid patterns

        if matches[attack_type]:
            # Calculate confidence based on pattern strength and count
            pattern_count = len(matches[attack_type])

            # Base confidence on pattern matches
            if attack_type in ["sqli", "command_injection"]:
                confidence = min(0.4 + (pattern_count * 0.2), 0.95)
            elif attack_type in ["xss", "path_traversal"]:
                confidence = min(0.35 + (pattern_count * 0.15), 0.85)
            elif attack_type == "brute_force":
                confidence = min(0.2 + (pattern_count * 0.1), 0.7)
            else:  # reconnaissance
                confidence = min(0.15 + (pattern_count * 0.1), 0.6)

            # If this attack type has higher confidence, use it
            if confidence > max_confidence:
                max_confidence = confidence
                best_attack_type = attack_type
                best_indicators = matches[attack_type]

    # Determine action and severity based on attack type and confidence
    if best_attack_type == "sqli" and max_confidence > 0.4:
        action = "block_ip"
        severity = "critical"
    elif best_attack_type == "command_injection" and max_confidence > 0.4:
        action = "block_ip"
        severity = "critical"
    elif best_attack_type == "xss" and max_confidence > 0.3:
        action = "block_ip"
        severity = "high"
    elif best_attack_type == "path_traversal" and max_confidence > 0.3:
        action = "block_ip"
        severity = "high"
    elif best_attack_type == "brute_force" and max_confidence > 0.4:
        action = "block_ip"
        severity = "medium"
    elif best_attack_type == "reconnaissance":
        action = "monitor"
        severity = "low"
    else:
        action = "log_only"
        severity = "info"
        max_confidence = 0.0
        best_attack_type = "unknown"
        best_indicators = []

    return {
        "attack_type": best_attack_type,
        "confidence": max_confidence,
        "recommended_action": action,
        "explanation": f"Pattern-based analysis detected {best_attack_type}",
        "severity": severity,
        "indicators": best_indicators,
    }


async def analyze_attack_async(attack_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for attack analysis.

    Args:
        attack_data: Attack log data

    Returns:
        Analysis result
    """
    # Use LLM if available, otherwise pattern matching
    analysis_result = await analyze_attack_with_llm(attack_data)

    # Store in knowledge base
    try:
        attack_id = knowledge_base.store_analysis(attack_data, analysis_result)
        analysis_result["attack_id"] = attack_id
    except Exception as exc:
        logger.error(f"Failed to store analysis: {exc}")

    # Apply adaptive defense
    await apply_adaptive_defense(attack_data, analysis_result)

    return analysis_result


async def apply_adaptive_defense(attack_data: Dict[str, Any], analysis_result: Dict[str, Any]) -> None:
    """
    Apply adaptive defense based on analysis results.

    Args:
        attack_data: Original attack data
        analysis_result: Analysis results
    """
    attack_type = analysis_result.get("attack_type", "unknown")
    confidence = analysis_result.get("confidence", 0.0)
    action = analysis_result.get("recommended_action", "log_only")

    # Extract patterns for future detection
    if confidence > 0.7 and attack_type != "unknown":
        # Add suspicious path patterns
        path = attack_data.get("path", "")
        if len(path) > 10 and "?" in path:  # Has query parameters
            # Extract potential attack patterns from path
            if "=" in path:
                params = path.split("?")[1] if "?" in path else path
                for param in params.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        if len(value) > 20:  # Long suspicious values
                            pattern = re.escape(value[:50])  # First 50 chars
                            adaptive_defense.add_pattern(attack_type, pattern)

    # Add decoy endpoints based on reconnaissance
    if attack_type == "reconnaissance" and confidence > 0.5:
        path = attack_data.get("path", "")
        if path.startswith("/"):
            # Create similar decoy endpoints
            decoy_variants = [
                path.replace(".php", ".bak"),
                path.replace(".php", ".old"),
                path + ".backup",
                path + "~",
            ]
            for decoy in decoy_variants:
                if decoy not in adaptive_defense.decoy_endpoints:
                    adaptive_defense.add_decoy_endpoint(decoy)

    # IP blocking based on recommended action
    if action == "block_ip":
        ip = attack_data.get("ip_address")
        if ip:
            adaptive_defense.block_ip(ip)


# FastAPI router for analysis endpoints

router = APIRouter(prefix="/analysis", tags=["analysis"])


@router.get("/recent")
async def get_recent_analyses(limit: int = 10) -> Dict[str, Any]:
    """Get recent attack analyses."""
    try:
        analyses = knowledge_base.get_recent_analyses(limit)
        return {"analyses": analyses, "count": len(analyses), "limit": limit}
    except Exception as exc:
        logger.error(f"Failed to get recent analyses: {exc}")
        return {"error": str(exc)}


@router.get("/stats")
async def get_attack_stats(days: int = 7) -> Dict[str, Any]:
    """Get attack statistics."""
    try:
        stats = knowledge_base.get_attack_stats(days)
        return stats
    except Exception as exc:
        logger.error(f"Failed to get attack stats: {exc}")
        return {"error": str(exc)}


@router.post("/feedback/{attack_id}")
async def add_feedback(attack_id: int, feedback_data: Dict[str, str]) -> Dict[str, Any]:
    """Add feedback to an attack analysis."""
    try:
        feedback = feedback_data.get("feedback", "")
        success = knowledge_base.update_feedback(attack_id, feedback)
        return {"success": success, "attack_id": attack_id}
    except Exception as exc:
        logger.error(f"Failed to add feedback: {exc}")
        return {"error": str(exc)}


@router.get("/patterns")
async def get_patterns() -> Dict[str, Any]:
    """Get current attack detection patterns."""
    return {
        "static_patterns": ATTACK_PATTERNS,
        "dynamic_patterns": adaptive_defense.dynamic_patterns,
        "blocked_ips": list(adaptive_defense.blocked_ips),
        "decoy_endpoints": list(adaptive_defense.decoy_endpoints),
    }
