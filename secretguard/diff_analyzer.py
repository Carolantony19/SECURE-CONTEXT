"""
Diff-aware placeholder-swap detection for the current staged change.

Compares each variable's committed value (HEAD) against its staged value
and flags placeholder → high-entropy substitutions.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

from secretguard.config import ScanConfig
from secretguard.placeholders import placeholder_swap_detected
from secretguard.scanner import Finding, _EXTENSION_PATTERNS, _PY_ASSIGN

logger = logging.getLogger(__name__)


def _get_old_content(repo_root: Path, filepath: Path) -> Optional[str]:
    """Retrieve the HEAD-committed version of *filepath* via GitPython."""
    try:
        import git
        repo = git.Repo(repo_root, search_parent_directories=True)
        rel = str(filepath.relative_to(Path(repo.working_dir))).replace("\\", "/")
        blob = repo.head.commit.tree / rel
        return blob.data_stream.read().decode("utf-8", errors="replace")
    except Exception:
        return None


def _build_var_map(content: str, filepath: Path) -> dict[str, str]:
    """Scan *content* and return {variable_name: raw_value}."""
    ext = filepath.suffix.lower()
    patterns = _EXTENSION_PATTERNS.get(ext, [_PY_ASSIGN])
    var_map: dict[str, str] = {}
    for line in content.splitlines():
        for pattern in patterns:
            match = pattern.search(line)
            if match:
                var = match.group("var")
                if var:
                    var_map[var] = match.group("val").strip()
    return var_map


def enrich_with_diff(
    findings: list[Finding],
    repo_root: Path,
    config: Optional[ScanConfig] = None,
) -> list[Finding]:
    """Enrich findings with placeholder-swap detection from git diff.

    For each finding, checks whether the same variable existed in HEAD
    with a placeholder value.  Sets ``finding.placeholder_swap = True``
    when a swap is detected.
    """
    config = config or ScanConfig()

    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)

    for filepath_str, file_findings in by_file.items():
        filepath = Path(filepath_str)
        old_content = _get_old_content(repo_root, filepath)
        if old_content is None:
            continue

        old_vars = _build_var_map(old_content, filepath)

        for finding in file_findings:
            old_val = old_vars.get(finding.variable)
            if old_val is None:
                continue
            if placeholder_swap_detected(old_val, finding.raw_value):
                finding.placeholder_swap = True
                finding.reason += (
                    f" Placeholder swap: '{old_val}' → "
                    f"'{finding.masked_value or finding.raw_value[:6]}…'"
                )

    return findings


def get_staged_files(repo_root: Path) -> list[Path]:
    """Return absolute paths of staged files in the git repo."""
    try:
        import git
        repo = git.Repo(repo_root, search_parent_directories=True)
        working_dir = Path(repo.working_dir)

        try:
            diffs = repo.index.diff("HEAD")
        except Exception:
            # No HEAD (initial commit) — all indexed files are "new".
            return [
                working_dir / entry[0]
                for entry in repo.index.entries
                if (working_dir / entry[0]).is_file()
            ]

        staged_paths: list[Path] = []
        for diff in diffs:
            path = working_dir / (diff.a_path or diff.b_path)
            if path.is_file():
                staged_paths.append(path)

        return staged_paths
    except Exception as exc:
        logger.warning("Could not read staged files: %s", exc)
        return []
