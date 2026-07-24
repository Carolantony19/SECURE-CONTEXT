"""
SecretGuard-AI: Pre-commit security tool for detecting hardcoded secrets
introduced through AI-assisted coding workflows.

Detects placeholder-to-real-value substitution — a behavioral signal that
static regex scanners (GitLeaks, TruffleHog) miss.
"""

__version__ = "0.1.0"
__all__ = [
    "scanner",
    "entropy",
    "placeholders",
    "diff_analyzer",
    "risk_scorer",
    "report",
    "config",
    "cli",
]
