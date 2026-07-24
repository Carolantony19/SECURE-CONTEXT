"""
Placeholder pattern library for SecretGuard AI.

AI-assisted coding tools (Copilot, ChatGPT, Gemini) routinely emit
placeholder tokens such as ``YOUR_API_KEY_HERE``, ``<INSERT_TOKEN>``,
``REPLACE_ME``, or ``xxx``.  These are *safe*.  The danger arises when a
developer **replaces** one of these placeholders with a real secret and
commits the change.

This module provides:
1. A curated library of known placeholder patterns (regex).
2. A function to classify any string as "placeholder" or "potentially real".
3. Placeholder-swap detection helpers used by diff/history analysers.
"""

from __future__ import annotations

import re
from typing import Optional

# ── Built-in placeholder patterns (compiled case-insensitive) ──────────────

_RAW_PATTERNS: list[str] = [
    # Explicit "insert here" markers
    r"YOUR[_\-]?\w*[_\-]?HERE",
    r"<[A-Z_\-]+>",
    r"\{[A-Z_\-]+\}",
    r"REPLACE[_\-]?ME",
    r"INSERT[_\-]?\w*[_\-]?HERE",
    r"PUT[_\-]?\w*[_\-]?HERE",
    r"CHANGEME",
    r"TODO[_:\-\s].*",
    r"FIXME[_:\-\s].*",
    # Common dummy/example values
    r"xxx+",
    r"example[_\-]?\w*",
    r"sample[_\-]?\w*",
    r"test[_\-]?(?:key|token|secret|api)",
    r"dummy[_\-]?\w*",
    r"fake[_\-]?\w*",
    r"placeholder",
    r"default[_\-]?(?:key|token|secret)",
    # Ellipsis / redacted markers
    r"\.{3,}",
    r"\*{3,}",
    r"REDACTED",
    r"REMOVED",
    r"CENSORED",
    # "sk-" prefixed fakes that AI models often generate
    r"sk-(?:fake|test|example|dummy|xxx)[_\-]?\w*",
]

_COMPILED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(rf"^{p}$", re.IGNORECASE) for p in _RAW_PATTERNS
]


def is_placeholder(value: str, extra_patterns: Optional[list[str]] = None) -> bool:
    """Return True if *value* matches any known placeholder pattern."""
    stripped = value.strip().strip("'\"")
    for pattern in _COMPILED_PATTERNS:
        if pattern.search(stripped):
            return True
    if extra_patterns:
        for raw in extra_patterns:
            try:
                if re.search(raw, stripped, re.IGNORECASE):
                    return True
            except re.error:
                continue
    return False


def classify_value(value: str) -> str:
    """Classify a value as ``'placeholder'``, ``'empty'``, or ``'candidate'``."""
    stripped = value.strip().strip("'\"")
    if not stripped:
        return "empty"
    if is_placeholder(stripped):
        return "placeholder"
    return "candidate"


def placeholder_swap_detected(old_value: str, new_value: str) -> bool:
    """Detect if a placeholder was swapped for a potentially real value.

    This is the **key behavioral signal**: the old value was a placeholder
    and the new value is a non-placeholder candidate.
    """
    if old_value == new_value:
        return False
    old_class = classify_value(old_value)
    new_class = classify_value(new_value)
    return old_class == "placeholder" and new_class == "candidate"
