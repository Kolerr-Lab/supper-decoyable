"""
decoyable/defense/knowledge_base.py

SQLite-based knowledge base for attack analysis and learning.
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class KnowledgeBase:
    """SQLite-based knowledge base for attack analysis and learning."""

    def __init__(self, db_path: str = "decoyable_knowledge.db"):
        self.db_path = Path(db_path)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema."""
        import sqlite3

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
        import sqlite3

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

    def store_attack(self, attack_data: Dict[str, Any]) -> int:
        """Store raw attack data in knowledge base."""
        import sqlite3

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                INSERT INTO attacks (timestamp, attack_data, analysis_result, created_at)
                VALUES (?, ?, ?, ?)
            """,
                (
                    attack_data.get("timestamp", datetime.utcnow().isoformat()),
                    json.dumps(attack_data),
                    json.dumps({}),  # Empty analysis for now
                    datetime.utcnow().timestamp(),
                ),
            )
            return cursor.lastrowid

    def store_alert(self, alert_data: Dict[str, Any]) -> int:
        """Store security alert in knowledge base."""
        import sqlite3

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                INSERT INTO attacks (timestamp, attack_data, analysis_result, created_at)
                VALUES (?, ?, ?, ?)
            """,
                (
                    alert_data.get("timestamp", datetime.utcnow().isoformat()),
                    json.dumps(alert_data),
                    json.dumps({"alert_type": alert_data.get("alert_type", "unknown")}),
                    datetime.utcnow().timestamp(),
                ),
            )
            return cursor.lastrowid

    def get_recent_analyses(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent attack analyses."""
        import sqlite3

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
                        "attack_data": json.loads(attack_data) if attack_data else {},
                        "analysis_result": json.loads(analysis_result) if analysis_result else {},
                        "feedback": feedback,
                    }
                )
            return results

    def get_attack_stats(self, days: int = 7) -> Dict[str, Any]:
        """Get attack statistics for the last N days."""
        import sqlite3

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
        import sqlite3

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
