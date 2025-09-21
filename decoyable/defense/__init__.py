"""
decoyable/defense

Active cyber defense module for DECOYABLE.
Provides honeypot endpoints, LLM analysis, and adaptive defense capabilities.
"""

from .honeypot import router as honeypot_router
from .analysis import router as analysis_router

__all__ = ["honeypot_router", "analysis_router"]