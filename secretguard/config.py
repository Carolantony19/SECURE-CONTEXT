"""
Configuration loader for SecretGuard AI.

Loads settings from three sources, in priority order:
1. CLI flags (highest priority)
2. ``secretguard.toml`` in the project root
3. Built-in defaults (lowest priority)

Also loads the ``.secretguardignore`` allowlist via :mod:`secretguard.allowlist`.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

# Python 3.11+ ships tomllib in the stdlib; earlier versions need tomli.
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]


# ── Defaults ────────────────────────────────────────────────────────────────

DEFAULT_ENTROPY_THRESHOLD: float = 4.5
DEFAULT_SCAN_EXTENSIONS: frozenset[str] = frozenset(
    {".py", ".js", ".ts", ".env", ".yaml", ".yml", ".json",
     ".toml", ".cfg", ".ini", ".tf"}
)
DEFAULT_SCAN_FILENAMES: frozenset[str] = frozenset(
    {"Dockerfile", ".env", ".env.local", ".env.production"}
)
DEFAULT_EXCLUDE_PATTERNS: list[str] = [
    "node_modules/**", ".git/**", "__pycache__/**", "*.pyc",
    "venv/**", ".venv/**", "dist/**", "build/**",
    "*.egg-info/**", ".tox/**", "*.lock", "*.min.js",
]
MIN_SECRET_LENGTH: int = 8
MAX_FILE_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB
MAX_TERMINAL_FINDINGS: int = 100


@dataclass
class CustomRule:
    """A user-defined regex detection rule from ``secretguard.toml``."""
    id: str
    pattern: str
    description: str = ""
    severity: str = "HIGH"


@dataclass
class ScanConfig:
    """Runtime scan configuration — merged from defaults, TOML, and CLI."""

    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD
    scan_extensions: set[str] = field(
        default_factory=lambda: set(DEFAULT_SCAN_EXTENSIONS)
    )
    scan_filenames: set[str] = field(
        default_factory=lambda: set(DEFAULT_SCAN_FILENAMES)
    )
    exclude_patterns: list[str] = field(
        default_factory=lambda: list(DEFAULT_EXCLUDE_PATTERNS)
    )
    min_secret_length: int = MIN_SECRET_LENGTH
    max_file_size: int = MAX_FILE_SIZE_BYTES
    max_findings: int = MAX_TERMINAL_FINDINGS

    # Output
    output_format: str = "terminal"  # terminal | json | sarif
    output_file: Optional[Path] = None
    verbose: bool = False

    # Behaviour
    block_on_high: bool = True
    parallel_workers: int = 4

    # Extensibility
    extra_placeholder_patterns: list[str] = field(default_factory=list)
    custom_rules: list[CustomRule] = field(default_factory=list)
    allowlist_paths: list[str] = field(default_factory=list)

    # ── Loaders ─────────────────────────────────────────────────────────

    @classmethod
    def from_toml(cls, path: Path) -> "ScanConfig":
        """Load configuration from a ``secretguard.toml`` file."""
        if tomllib is None:
            return cls()
        try:
            raw = path.read_bytes()
            data: dict[str, Any] = tomllib.loads(raw.decode("utf-8"))
        except Exception:
            return cls()

        scan_section = data.get("scan", {})
        rules_section = data.get("rules", [])

        custom_rules = []
        for r in rules_section:
            custom_rules.append(CustomRule(
                id=r.get("id", "custom"),
                pattern=r.get("pattern", ""),
                description=r.get("description", ""),
                severity=r.get("severity", "HIGH"),
            ))

        return cls(
            entropy_threshold=scan_section.get(
                "entropy_threshold", DEFAULT_ENTROPY_THRESHOLD
            ),
            scan_extensions=set(
                scan_section.get("extensions", DEFAULT_SCAN_EXTENSIONS)
            ),
            exclude_patterns=scan_section.get(
                "exclude", DEFAULT_EXCLUDE_PATTERNS
            ),
            min_secret_length=scan_section.get(
                "min_secret_length", MIN_SECRET_LENGTH
            ),
            max_file_size=scan_section.get(
                "max_file_size", MAX_FILE_SIZE_BYTES
            ),
            parallel_workers=scan_section.get("parallel_workers", 4),
            extra_placeholder_patterns=scan_section.get(
                "extra_placeholders", []
            ),
            custom_rules=custom_rules,
            allowlist_paths=scan_section.get("allowlist_paths", []),
        )

    @classmethod
    def load(cls, root: Path) -> "ScanConfig":
        """Auto-discover ``secretguard.toml`` from *root* and load it."""
        toml_path = root / "secretguard.toml"
        if toml_path.is_file():
            return cls.from_toml(toml_path)
        return cls()
