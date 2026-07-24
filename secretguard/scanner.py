"""
Regex-based scanner for secret-assignment patterns.

Scans source files for lines that look like credential assignments:
    api_key = "sk-..."
    export SECRET_TOKEN=ghp_...
    "password": "..."

Each match produces a :class:`Finding` with the variable name, raw value,
file path, and line number.  Down-stream modules (:mod:`entropy`,
:mod:`placeholders`, :mod:`risk_scorer`) enrich each finding with
quantitative risk signals.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from secretguard.config import ScanConfig, DEFAULT_SCAN_EXTENSIONS


# ── Data model ──────────────────────────────────────────────────────────────


@dataclass
class Finding:
    """A single potential secret detected in a source file."""

    file: str
    line_number: int
    variable: str
    raw_value: str

    # Enrichment fields (populated by downstream modules)
    entropy: float = 0.0
    is_placeholder: bool = False
    placeholder_swap: bool = False
    risk: str = "LOW"          # LOW | MEDIUM | HIGH
    reason: str = ""
    masked_value: str = ""

    def mask(self, reveal: int = 6) -> str:
        """Return a masked version of the raw value, showing only the first
        *reveal* characters followed by asterisks."""
        if len(self.raw_value) <= reveal:
            return self.raw_value
        self.masked_value = self.raw_value[:reveal] + "*" * (len(self.raw_value) - reveal)
        return self.masked_value


# ── Regex patterns ──────────────────────────────────────────────────────────
#
# We maintain per-language pattern sets because assignment syntax differs
# across file types.  All patterns capture two named groups:
#   - ``var``:   the variable / key name
#   - ``val``:   the assigned value (may include surrounding quotes)

_COMMON_KEY_NAMES = (
    r"(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token|auth[_\-]?token|"
    r"password|passwd|credential|private[_\-]?key|client[_\-]?secret|"
    r"db[_\-]?password|database[_\-]?url|connection[_\-]?string|"
    r"encryption[_\-]?key|signing[_\-]?key|jwt[_\-]?secret|"
    r"aws[_\-]?secret|github[_\-]?token|slack[_\-]?token|"
    r"stripe[_\-]?key|sendgrid[_\-]?key|twilio[_\-]?token|"
    r"api[_\-]?secret|token|secret|key)"
)

# Python / generic assignment:  var = "value"  or  var = 'value'
_PY_ASSIGN = re.compile(
    rf"(?:^|\s)(?P<var>\w*{_COMMON_KEY_NAMES}\w*)\s*=\s*['\"](?P<val>[^'\"]+)['\"]",
    re.IGNORECASE,
)

# Shell / .env export:  export VAR="value"  or  VAR=value
_ENV_ASSIGN = re.compile(
    rf"^(?:export\s+)?(?P<var>\w*{_COMMON_KEY_NAMES}\w*)\s*=\s*['\"]?(?P<val>[^'\"#\s]+)",
    re.IGNORECASE,
)

# JSON key-value:  "api_key": "value"
_JSON_KV = re.compile(
    rf'["\'](?P<var>\w*{_COMMON_KEY_NAMES}\w*)["\']\s*:\s*["\'](?P<val>[^"\']+)["\']',
    re.IGNORECASE,
)

# YAML key-value:  api_key: value  or  api_key: "value"
_YAML_KV = re.compile(
    rf"^(?P<var>\w*{_COMMON_KEY_NAMES}\w*)\s*:\s*['\"]?(?P<val>[^'\"#\n]+)",
    re.IGNORECASE,
)

# Map file extensions to the patterns that apply.
_EXTENSION_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    ".py":   [_PY_ASSIGN],
    ".js":   [_PY_ASSIGN],           # JS assignment syntax is close enough
    ".ts":   [_PY_ASSIGN],
    ".env":  [_ENV_ASSIGN],
    ".yaml": [_YAML_KV],
    ".yml":  [_YAML_KV],
    ".json": [_JSON_KV],
    ".toml": [_PY_ASSIGN],
    ".cfg":  [_PY_ASSIGN, _ENV_ASSIGN],
    ".ini":  [_PY_ASSIGN, _ENV_ASSIGN],
}


# ── Scanner entry point ────────────────────────────────────────────────────


def scan_file(filepath: Path, config: Optional[ScanConfig] = None) -> list[Finding]:
    """Scan a single file for secret-assignment patterns.

    Args:
        filepath: Path to the file to scan.
        config:   Optional scan configuration (for extension filtering,
                  min-length, etc.).

    Returns:
        A list of :class:`Finding` objects, one per suspected secret.
    """
    config = config or ScanConfig()
    ext = filepath.suffix.lower()

    if ext not in config.scan_extensions:
        return []

    patterns = _EXTENSION_PATTERNS.get(ext, [_PY_ASSIGN])

    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return []

    findings: list[Finding] = []

    for line_number, line in enumerate(content.splitlines(), start=1):
        for pattern in patterns:
            match = pattern.search(line)
            if match:
                var_name = match.group("var")
                raw_val = match.group("val").strip()

                # Skip very short values — not meaningful secrets.
                if len(raw_val) < config.min_secret_length:
                    continue

                finding = Finding(
                    file=str(filepath),
                    line_number=line_number,
                    variable=var_name,
                    raw_value=raw_val,
                )
                finding.mask()
                findings.append(finding)

    return findings


def scan_directory(
    root: Path,
    config: Optional[ScanConfig] = None,
) -> list[Finding]:
    """Recursively scan a directory for secrets.

    Respects ``config.exclude_patterns`` for path filtering.

    Args:
        root:   Root directory to scan.
        config: Optional scan configuration.

    Returns:
        Aggregated list of findings across all scanned files.
    """
    config = config or ScanConfig()
    findings: list[Finding] = []

    for filepath in root.rglob("*"):
        if not filepath.is_file():
            continue

        # Check exclusion patterns.
        rel = filepath.relative_to(root)
        if _is_excluded(rel, config.exclude_patterns):
            continue

        findings.extend(scan_file(filepath, config))

    return findings


def _is_excluded(rel_path: Path, patterns: list[str]) -> bool:
    """Return True if *rel_path* matches any exclusion glob pattern."""
    rel_str = str(rel_path).replace("\\", "/")
    for pattern in patterns:
        # Simple glob matching: fnmatch-style.
        import fnmatch
        if fnmatch.fnmatch(rel_str, pattern):
            return True
    return False
