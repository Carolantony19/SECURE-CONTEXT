"""
Placeholder pattern library for SecretGuard-AI.

AI-assisted coding tools (Copilot, ChatGPT, Gemini) routinely emit
placeholder tokens such as ``YOUR_API_KEY_HERE``, ``<INSERT_TOKEN>``,
``REPLACE_ME``, or ``xxx``.  These are *safe* — they contain no real
credentials.  The danger arises when a developer **replaces** one of
these placeholders with a real secret and then commits the change.

This module provides:

1. A curated library of known placeholder patterns (regex).
2. A function to classify any string as "placeholder" or "potentially real".
3. Placeholder-swap detection helpers used by :mod:`secretguard.diff_analyzer`.

**Placeholder-swap logic (key differentiator):**
    If a variable held a placeholder in the *previous* commit and now holds
    a high-entropy value, that substitution is a strong behavioral signal
    of an accidentally committed secret.  Static regex tools cannot detect
    this because they only see the *current* snapshot.
"""

from __future__ import annotations

import re
from typing import Optional


# ── Built-in placeholder patterns ──────────────────────────────────────────
#
# Each pattern is compiled as case-insensitive.  They are ordered from most
# specific (exact match) to most general (substring match).

_RAW_PATTERNS: list[str] = [
    # Explicit "insert here" markers
    r"YOUR[_\-]?\w*[_\-]?HERE",            # YOUR_API_KEY_HERE, YOUR-TOKEN-HERE
    r"<[A-Z_\-]+>",                         # <API_KEY>, <INSERT_TOKEN>
    r"\{[A-Z_\-]+\}",                       # {API_KEY}, {SECRET}
    r"REPLACE[_\-]?ME",                     # REPLACE_ME, REPLACEME
    r"INSERT[_\-]?\w*[_\-]?HERE",           # INSERT_KEY_HERE
    r"PUT[_\-]?\w*[_\-]?HERE",             # PUT_YOUR_KEY_HERE
    r"CHANGEME",
    r"TODO[_:\-\s]*\w*",                    # TODO: add key
    r"FIXME[_:\-\s]*\w*",

    # Common dummy/example values
    r"xxx+",                                 # xxx, xxxx, xxxxx
    r"example[_\-]?\w*",                    # example_key, example-token
    r"sample[_\-]?\w*",                     # sample_key
    r"test[_\-]?(?:key|token|secret|api)",  # test_key, test-token
    r"dummy[_\-]?\w*",                      # dummy_key
    r"fake[_\-]?\w*",                       # fake_token
    r"placeholder",
    r"default[_\-]?(?:key|token|secret)",   # default_key

    # Ellipsis / redacted markers
    r"\.{3,}",                               # ... or ....
    r"\*{3,}",                               # *** or ****
    r"REDACTED",
    r"REMOVED",
    r"CENSORED",

    # "sk-" prefixed fakes that AI models often generate
    r"sk-(?:fake|test|example|dummy|xxx)[_\-]?\w*",
]

# Pre-compile all patterns for performance.
_COMPILED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(rf"^{p}$", re.IGNORECASE) for p in _RAW_PATTERNS
]


def is_placeholder(value: str, extra_patterns: Optional[list[str]] = None) -> bool:
    """Return True if *value* matches any known placeholder pattern.

    Args:
        value:          The candidate string (stripped of surrounding quotes).
        extra_patterns: Optional additional regex strings to match against
                        (from user config).

    Returns:
        True if the value looks like a placeholder, False otherwise.

    Examples:
        >>> is_placeholder("YOUR_API_KEY_HERE")
        True
        >>> is_placeholder("sk-fake000000000000000000000000")
        True
        >>> is_placeholder("ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6")
        False
    """
    stripped = value.strip().strip("'\"")

    # Check built-in patterns.
    for pattern in _COMPILED_PATTERNS:
        if pattern.search(stripped):
            return True

    # Check user-supplied extra patterns.
    if extra_patterns:
        for raw in extra_patterns:
            if re.search(raw, stripped, re.IGNORECASE):
                return True

    return False


def classify_value(value: str) -> str:
    """Classify a value as ``'placeholder'``, ``'empty'``, or ``'candidate'``.

    - ``'empty'``:       Zero-length or whitespace-only.
    - ``'placeholder'``: Matches a known placeholder pattern.
    - ``'candidate'``:   Potentially a real secret — needs entropy scoring.
    """
    stripped = value.strip().strip("'\"")
    if not stripped:
        return "empty"
    if is_placeholder(stripped):
        return "placeholder"
    return "candidate"


def placeholder_swap_detected(old_value: str, new_value: str) -> bool:
    """Detect if a placeholder was swapped for a potentially real value.

    **This is the key behavioral signal** that distinguishes SecretGuard
    from static scanners:

    1. The *old* value (from the last committed version) was a placeholder.
    2. The *new* value (in the staged/working version) is NOT a placeholder.
    3. The two values are different.

    The caller (:mod:`secretguard.diff_analyzer`) should additionally verify
    that the new value has high entropy before flagging.

    Args:
        old_value: Value from the previous commit.
        new_value: Value from the current staged file.

    Returns:
        True if this looks like a placeholder → real-value substitution.
    """
    if old_value == new_value:
        return False

    old_class = classify_value(old_value)
    new_class = classify_value(new_value)

    # Swap detected: old was a placeholder, new is a candidate (not another placeholder).
    return old_class == "placeholder" and new_class == "candidate"
