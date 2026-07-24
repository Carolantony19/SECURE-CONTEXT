"""
Allowlist support for SecretGuard AI.

Reads a ``.secretguardignore`` file (one pattern per line, comments with ``#``)
and provides a function to check whether a finding should be suppressed.

Patterns can be:
- A file glob:        ``tests/fixtures/*``
- A variable name:    ``EXAMPLE_KEY``
- A fingerprint:      ``sha256:<hex>``  (hash of the raw value)
"""

from __future__ import annotations

import fnmatch
import hashlib
from pathlib import Path


def load_allowlist(root: Path) -> list[str]:
    """Load patterns from ``.secretguardignore`` at *root*.

    Returns a list of non-empty, non-comment lines.
    """
    ignore_file = root / ".secretguardignore"
    if not ignore_file.is_file():
        return []

    patterns: list[str] = []
    try:
        for line in ignore_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                patterns.append(stripped)
    except (OSError, UnicodeDecodeError):
        pass

    return patterns


def is_allowed(
    *,
    filepath: str,
    variable: str,
    raw_value: str,
    patterns: list[str],
) -> bool:
    """Return True if the finding matches any allowlist pattern.

    Matching logic:
    - If pattern starts with ``sha256:``, compare against the SHA-256
      hex digest of *raw_value*.
    - If pattern looks like a glob (contains ``*``, ``?``, ``/``),
      match against *filepath* (using forward-slash normalised paths).
    - Otherwise, match against *variable* name (exact, case-insensitive).
    """
    value_hash = hashlib.sha256(raw_value.encode("utf-8")).hexdigest()
    norm_path = filepath.replace("\\", "/")

    for pat in patterns:
        # Fingerprint match
        if pat.startswith("sha256:"):
            if pat[7:].strip().lower() == value_hash:
                return True
            continue

        # Glob / path match
        if any(c in pat for c in ("*", "?", "/")):
            if fnmatch.fnmatch(norm_path, pat):
                return True
            continue

        # Variable name match
        if pat.lower() == variable.lower():
            return True

    return False
