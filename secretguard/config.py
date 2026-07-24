"""
Configuration module for SecretGuard-AI.

Centralizes all tunable parameters: entropy thresholds, file extensions,
path exclusions, and output preferences. Every other module imports from here
rather than hardcoding magic numbers.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── Default values ──────────────────────────────────────────────────────────

#: Shannon entropy threshold (bits). Values above this are considered
#: "high-entropy" — likely real credentials rather than English words or
#: simple placeholders. Empirically, English text ≈ 3.5–4.5 bits;
#: base64/hex secrets ≈ 4.5–6.0 bits.
DEFAULT_ENTROPY_THRESHOLD: float = 4.5

#: File extensions the scanner considers by default.
DEFAULT_SCAN_EXTENSIONS: frozenset[str] = frozenset(
    {".py", ".js", ".ts", ".env", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini"}
)

#: Glob patterns for paths to ignore during scans.
DEFAULT_EXCLUDE_PATTERNS: list[str] = [
    "node_modules/**",
    ".git/**",
    "__pycache__/**",
    "*.pyc",
    "venv/**",
    ".venv/**",
    "dist/**",
    "build/**",
    "*.egg-info/**",
    ".tox/**",
    "*.lock",
]

#: Minimum length for a value to be worth scoring for entropy.
#: Very short strings (≤8 chars) rarely contain meaningful secrets.
MIN_SECRET_LENGTH: int = 8

#: Maximum number of findings shown in the terminal summary before
#: truncating with "… and N more".
MAX_TERMINAL_FINDINGS: int = 50


# ── Runtime configuration dataclass ────────────────────────────────────────


@dataclass
class ScanConfig:
    """Runtime-mutable scan configuration.

    Construct with defaults, then override from CLI flags or a config file.
    """

    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD
    scan_extensions: set[str] = field(
        default_factory=lambda: set(DEFAULT_SCAN_EXTENSIONS)
    )
    exclude_patterns: list[str] = field(
        default_factory=lambda: list(DEFAULT_EXCLUDE_PATTERNS)
    )
    min_secret_length: int = MIN_SECRET_LENGTH
    max_findings: int = MAX_TERMINAL_FINDINGS

    # Output controls
    json_output: Optional[Path] = None
    html_output: Optional[Path] = None
    verbose: bool = False

    # Pre-commit mode: when True, a HIGH finding causes non-zero exit.
    block_on_high: bool = True

    # Custom placeholder patterns (merged with built-in library).
    extra_placeholder_patterns: list[str] = field(default_factory=list)

    # ── Persistence ─────────────────────────────────────────────────────

    @classmethod
    def from_file(cls, path: Path) -> "ScanConfig":
        """Load configuration from a JSON file, falling back to defaults
        for any missing keys."""
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            entropy_threshold=data.get("entropy_threshold", DEFAULT_ENTROPY_THRESHOLD),
            scan_extensions=set(
                data.get("scan_extensions", DEFAULT_SCAN_EXTENSIONS)
            ),
            exclude_patterns=data.get("exclude_patterns", DEFAULT_EXCLUDE_PATTERNS),
            min_secret_length=data.get("min_secret_length", MIN_SECRET_LENGTH),
            max_findings=data.get("max_findings", MAX_TERMINAL_FINDINGS),
            verbose=data.get("verbose", False),
            block_on_high=data.get("block_on_high", True),
            extra_placeholder_patterns=data.get("extra_placeholder_patterns", []),
        )

    def to_dict(self) -> dict:
        """Serialize to a JSON-friendly dict."""
        return {
            "entropy_threshold": self.entropy_threshold,
            "scan_extensions": sorted(self.scan_extensions),
            "exclude_patterns": self.exclude_patterns,
            "min_secret_length": self.min_secret_length,
            "max_findings": self.max_findings,
            "verbose": self.verbose,
            "block_on_high": self.block_on_high,
            "extra_placeholder_patterns": self.extra_placeholder_patterns,
        }
