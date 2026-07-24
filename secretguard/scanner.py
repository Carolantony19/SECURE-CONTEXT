"""
Regex-based scanner for secret-assignment patterns.

Production-grade: parallel scanning via ``concurrent.futures``, graceful
handling of binary files (>10 MB), non-UTF-8 encodings, symlinks, and
permission errors.  Supports .py, .js, .ts, .env, .yaml, .json, .toml,
Dockerfile, and Terraform (.tf) files.
"""

from __future__ import annotations

import fnmatch
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from secretguard.config import ScanConfig

logger = logging.getLogger(__name__)


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
    risk: str = "LOW"
    reason: str = ""
    masked_value: str = ""
    commit_sha: str = ""     # For history-based findings
    rule_id: str = ""        # For custom-rule matches

    def mask(self, reveal: int = 6) -> str:
        """Return a masked version showing only the first *reveal* characters."""
        if len(self.raw_value) <= reveal:
            self.masked_value = self.raw_value
        else:
            self.masked_value = (
                self.raw_value[:reveal] + "*" * (len(self.raw_value) - reveal)
            )
        return self.masked_value


# ── Regex patterns ──────────────────────────────────────────────────────────

_COMMON_KEY_NAMES = (
    r"(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token|auth[_\-]?token|"
    r"password|passwd|credential|private[_\-]?key|client[_\-]?secret|"
    r"db[_\-]?password|database[_\-]?url|connection[_\-]?string|"
    r"encryption[_\-]?key|signing[_\-]?key|jwt[_\-]?secret|"
    r"aws[_\-]?secret|github[_\-]?token|slack[_\-]?token|"
    r"stripe[_\-]?key|sendgrid[_\-]?key|twilio[_\-]?token|"
    r"api[_\-]?secret|token|secret|key)"
)

_PY_ASSIGN = re.compile(
    rf"(?:^|\s)(?P<var>\w*{_COMMON_KEY_NAMES}\w*)\s*=\s*['\"](?P<val>[^'\"]+)['\"]",
    re.IGNORECASE,
)

_ENV_ASSIGN = re.compile(
    rf"^(?:export\s+)?(?P<var>\w*{_COMMON_KEY_NAMES}\w*)\s*=\s*['\"]?(?P<val>[^'\"#\s]+)",
    re.IGNORECASE,
)

_JSON_KV = re.compile(
    rf'["\'](?P<var>\w*{_COMMON_KEY_NAMES}\w*)["\']\s*:\s*["\'](?P<val>[^"\']+)["\']',
    re.IGNORECASE,
)

_YAML_KV = re.compile(
    rf"^(?P<var>\w*{_COMMON_KEY_NAMES}\w*)\s*:\s*['\"]?(?P<val>[^'\"#\n]+)",
    re.IGNORECASE,
)

# Dockerfile: ENV SECRET_KEY=value or ARG SECRET_KEY=value
_DOCKER_ASSIGN = re.compile(
    rf"^(?:ENV|ARG)\s+(?P<var>\w*{_COMMON_KEY_NAMES}\w*)\s*=\s*['\"]?(?P<val>[^'\"#\s]+)",
    re.IGNORECASE,
)

# Terraform: variable default, or direct assignment
_TF_ASSIGN = re.compile(
    rf'(?:default|(?P<var>\w*{_COMMON_KEY_NAMES}\w*))\s*=\s*"(?P<val>[^"]+)"',
    re.IGNORECASE,
)

_EXTENSION_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    ".py":   [_PY_ASSIGN],
    ".js":   [_PY_ASSIGN],
    ".ts":   [_PY_ASSIGN],
    ".env":  [_ENV_ASSIGN],
    ".yaml": [_YAML_KV],
    ".yml":  [_YAML_KV],
    ".json": [_JSON_KV],
    ".toml": [_PY_ASSIGN],
    ".cfg":  [_PY_ASSIGN, _ENV_ASSIGN],
    ".ini":  [_PY_ASSIGN, _ENV_ASSIGN],
    ".tf":   [_TF_ASSIGN],
}

_FILENAME_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "Dockerfile": [_DOCKER_ASSIGN],
    ".env": [_ENV_ASSIGN],
    ".env.local": [_ENV_ASSIGN],
    ".env.production": [_ENV_ASSIGN],
}


# ── File safety helpers ─────────────────────────────────────────────────────


def _is_binary(filepath: Path, sample_size: int = 8192) -> bool:
    """Heuristic: file is binary if the first *sample_size* bytes contain NUL."""
    try:
        chunk = filepath.read_bytes()[:sample_size]
        return b"\x00" in chunk
    except (OSError, PermissionError):
        return True  # Treat unreadable files as binary (skip).


def _read_safe(filepath: Path) -> Optional[str]:
    """Read a file with graceful encoding fallback. Returns None on failure."""
    for encoding in ("utf-8", "latin-1"):
        try:
            return filepath.read_text(encoding=encoding)
        except (UnicodeDecodeError, UnicodeError):
            continue
        except (OSError, PermissionError) as exc:
            logger.debug("Cannot read %s: %s", filepath, exc)
            return None
    return None


def _is_excluded(rel_path: Path, patterns: list[str]) -> bool:
    """Return True if *rel_path* matches any exclusion glob pattern."""
    rel_str = str(rel_path).replace("\\", "/")
    for pattern in patterns:
        if fnmatch.fnmatch(rel_str, pattern):
            return True
    return False


def _get_patterns(filepath: Path) -> list[re.Pattern[str]]:
    """Resolve regex patterns for a given file (by extension or name)."""
    name = filepath.name
    if name in _FILENAME_PATTERNS:
        return _FILENAME_PATTERNS[name]
    ext = filepath.suffix.lower()
    return _EXTENSION_PATTERNS.get(ext, [_PY_ASSIGN])


def _should_scan(filepath: Path, config: ScanConfig) -> bool:
    """Determine if a file should be scanned based on extension/name."""
    if filepath.name in config.scan_filenames:
        return True
    return filepath.suffix.lower() in config.scan_extensions


# ── Core scan logic ─────────────────────────────────────────────────────────


def scan_content(
    content: str,
    filepath: Path,
    config: Optional[ScanConfig] = None,
) -> list[Finding]:
    """Scan file *content* using patterns appropriate for *filepath*.

    This is the inner scanning function, also used by history_analyzer
    to scan historical file blobs without touching the filesystem.
    """
    config = config or ScanConfig()
    patterns = _get_patterns(filepath)
    findings: list[Finding] = []

    # Also try custom rules
    custom_compiled: list[tuple[re.Pattern[str], str, str]] = []
    for rule in config.custom_rules:
        try:
            custom_compiled.append((
                re.compile(rule.pattern, re.IGNORECASE),
                rule.id,
                rule.severity,
            ))
        except re.error:
            logger.warning("Invalid custom rule regex: %s", rule.pattern)

    for line_number, line in enumerate(content.splitlines(), start=1):
        # Built-in patterns
        for pattern in patterns:
            match = pattern.search(line)
            if match:
                var_name = match.group("var") or "unknown"
                raw_val = match.group("val").strip()
                if len(raw_val) < config.min_secret_length:
                    continue
                f = Finding(
                    file=str(filepath),
                    line_number=line_number,
                    variable=var_name,
                    raw_value=raw_val,
                )
                f.mask()
                findings.append(f)

        # Custom rules
        for compiled, rule_id, severity in custom_compiled:
            m = compiled.search(line)
            if m:
                raw = m.group(0)
                if len(raw) < config.min_secret_length:
                    continue
                f = Finding(
                    file=str(filepath),
                    line_number=line_number,
                    variable=f"custom:{rule_id}",
                    raw_value=raw,
                    rule_id=rule_id,
                )
                f.mask()
                findings.append(f)

    return findings


def scan_file(filepath: Path, config: Optional[ScanConfig] = None) -> list[Finding]:
    """Scan a single file for secret-assignment patterns.

    Gracefully skips binary files, files >max_file_size, and unreadable files.
    """
    config = config or ScanConfig()

    if not _should_scan(filepath, config):
        return []

    # Size guard
    try:
        size = filepath.stat().st_size
        if size > config.max_file_size:
            logger.debug("Skipping large file (%d bytes): %s", size, filepath)
            return []
    except OSError:
        return []

    # Binary guard
    if _is_binary(filepath):
        return []

    # Symlink guard (resolve but don't follow outside repo)
    if filepath.is_symlink():
        logger.debug("Skipping symlink: %s", filepath)
        return []

    content = _read_safe(filepath)
    if content is None:
        return []

    return scan_content(content, filepath, config)


def scan_directory(
    root: Path,
    config: Optional[ScanConfig] = None,
) -> list[Finding]:
    """Recursively scan a directory using parallel workers.

    Respects ``config.exclude_patterns`` and file-size/binary guards.
    """
    config = config or ScanConfig()
    files_to_scan: list[Path] = []

    for filepath in root.rglob("*"):
        if not filepath.is_file():
            continue
        try:
            rel = filepath.relative_to(root)
        except ValueError:
            continue
        if _is_excluded(rel, config.exclude_patterns):
            continue
        if not _should_scan(filepath, config):
            continue
        files_to_scan.append(filepath)

    # Parallel scanning
    all_findings: list[Finding] = []
    workers = min(config.parallel_workers, len(files_to_scan) or 1)

    if workers <= 1 or len(files_to_scan) <= 5:
        # Sequential for small sets (avoids thread overhead)
        for fp in files_to_scan:
            all_findings.extend(scan_file(fp, config))
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(scan_file, fp, config): fp
                for fp in files_to_scan
            }
            for future in as_completed(futures):
                try:
                    all_findings.extend(future.result())
                except Exception as exc:
                    logger.warning(
                        "Error scanning %s: %s", futures[future], exc
                    )

    return all_findings
