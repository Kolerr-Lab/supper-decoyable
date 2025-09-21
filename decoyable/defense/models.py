"""
decoyable/defense/models.py

Pydantic models for DECOYABLE defense system.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel


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