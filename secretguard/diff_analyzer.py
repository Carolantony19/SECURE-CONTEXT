"""
Diff-aware placeholder-swap detection via GitPython.

This module implements the **behavioral detection** layer that sets
SecretGuard apart from static regex scanners:

1. For each staged file, retrieve the file's content from the last commit
   (``HEAD``).
2. Re-scan the *old* content with the same regex patterns.
3. For each finding in the *new* (staged) content, look up whether the
   same variable existed in the old content.
4. If the old value was a **placeholder** and the new value is a
   **high-entropy candidate**, flag it as a **placeholder swap** — a
   strong signal of an accidentally committed real secret.

This detection is impossible for tools that only analyze a single
snapshot of the codebase.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from secretguard.config import ScanConfig
from secretguard.entropy import shannon_entropy
from secretguard.placeholders import placeholder_swap_detected
from secretguard.scanner import Finding, scan_file

logger = logging.getLogger(__name__)


def _get_old_content(repo_root: Path, filepath: Path) -> Optional[str]:
    """Retrieve the HEAD-committed version of *filepath* using GitPython.

    Returns ``None`` if the file is new (not in HEAD) or if GitPython
    is not available / the directory is not a git repo.
    """
    try:
        import git

        repo = git.Repo(repo_root, search_parent_directories=True)
        rel = filepath.relative_to(repo.working_dir)
        # Get the blob for this file at HEAD.
        blob = repo.head.commit.tree / str(rel).replace("\\", "/")
        return blob.data_stream.read().decode("utf-8", errors="replace")
    except Exception:
        # File is new, repo has no commits, GitPython unavailable, etc.
        return None


def _build_var_map(content: str, filepath: Path, config: ScanConfig) -> dict[str, str]:
    """Scan *content* (as if it were a file) and return {variable_name: raw_value}.

    We write the content to a temporary conceptual scan by reusing the
    scanner's regex logic on each line.
    """
    import re
    from secretguard.scanner import _EXTENSION_PATTERNS, _PY_ASSIGN

    ext = filepath.suffix.lower()
    patterns = _EXTENSION_PATTERNS.get(ext, [_PY_ASSIGN])
    var_map: dict[str, str] = {}

    for line in content.splitlines():
        for pattern in patterns:
            match = pattern.search(line)
            if match:
                var_map[match.group("var")] = match.group("val").strip()

    return var_map


def enrich_with_diff(
    findings: list[Finding],
    repo_root: Path,
    config: Optional[ScanConfig] = None,
) -> list[Finding]:
    """Enrich findings with placeholder-swap detection from git diff.

    For each finding, checks whether the same variable existed in the
    HEAD version of the file with a placeholder value.  If so, sets
    ``finding.placeholder_swap = True`` and appends context to
    ``finding.reason``.

    Args:
        findings:  Findings from :func:`scanner.scan_file` (already
                   enriched with entropy and placeholder flags).
        repo_root: Root of the git repository.
        config:    Scan configuration.

    Returns:
        The same list of findings, mutated in place with diff data.
    """
    config = config or ScanConfig()

    # Group findings by file to avoid redundant git lookups.
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)

    for filepath_str, file_findings in by_file.items():
        filepath = Path(filepath_str)
        old_content = _get_old_content(repo_root, filepath)

        if old_content is None:
            # New file — no previous version to compare.
            continue

        old_vars = _build_var_map(old_content, filepath, config)

        for finding in file_findings:
            old_val = old_vars.get(finding.variable)
            if old_val is None:
                # Variable didn't exist in the old version.
                continue

            if placeholder_swap_detected(old_val, finding.raw_value):
                finding.placeholder_swap = True
                finding.reason += (
                    f" Placeholder swap detected: "
                    f"'{old_val}' → '{finding.masked_value or finding.raw_value[:6]}…'"
                )
                logger.info(
                    "Placeholder swap: %s in %s (old=%r → new=%r)",
                    finding.variable,
                    finding.file,
                    old_val,
                    finding.raw_value[:8] + "…",
                )

    return findings


def get_staged_files(repo_root: Path) -> list[Path]:
    """Return a list of staged file paths in the git repo at *repo_root*.

    Uses GitPython to inspect the index (staging area).

    Returns:
        List of absolute Paths for staged files, or an empty list if
        GitPython is unavailable or the directory is not a git repo.
    """
    try:
        import git

        repo = git.Repo(repo_root, search_parent_directories=True)
        # Get diff between HEAD and index (staged changes).
        try:
            diffs = repo.index.diff("HEAD")
        except git.exc.BadName:
            # No HEAD yet (initial commit) — all indexed files are "new".
            return [
                Path(repo.working_dir) / item.a_path
                for item in repo.index.entries
            ]

        staged_paths: list[Path] = []
        for diff in diffs:
            # a_path is the file path relative to repo root.
            path = Path(repo.working_dir) / (diff.a_path or diff.b_path)
            if path.is_file():
                staged_paths.append(path)

        # Also include untracked but staged files (new files).
        for diff in repo.index.diff(None):
            path = Path(repo.working_dir) / (diff.a_path or diff.b_path)
            if path.is_file() and path not in staged_paths:
                staged_paths.append(path)

        return staged_paths
    except Exception as exc:
        logger.warning("Could not read staged files: %s", exc)
        return []
