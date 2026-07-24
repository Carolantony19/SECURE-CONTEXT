"""
Full git-history placeholder-lineage tracking for SecretGuard AI.

This is the project's **core differentiator**: walk the entire commit
history of a repository, track each secret-bearing variable's value
over time, and flag every point where a placeholder was replaced with
a high-entropy real value — even if that happened many commits ago.

Algorithm:
    1. ``git log --all --format=%H`` to get every commit SHA.
    2. For each commit, list changed files (``commit.stats.files``).
    3. For each changed file, scan the blob content with the regex scanner.
    4. Build a per-file, per-variable timeline: ``{(file, var): [(sha, value), ...]}``
    5. Walk each timeline; any transition from placeholder → high-entropy
       candidate is flagged as a lineage finding.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from secretguard.config import ScanConfig
from secretguard.entropy import shannon_entropy
from secretguard.placeholders import classify_value, placeholder_swap_detected
from secretguard.scanner import Finding, scan_content

logger = logging.getLogger(__name__)


@dataclass
class LineageEvent:
    """A single variable-value observation at a specific commit."""
    commit_sha: str
    value: str
    classification: str  # "placeholder" | "candidate" | "empty"


def analyze_history(
    repo_root: Path,
    config: Optional[ScanConfig] = None,
    max_commits: int = 5000,
) -> list[Finding]:
    """Walk the full git history and detect placeholder-to-secret swaps.

    Args:
        repo_root:   Root of the git repository.
        config:      Scan configuration.
        max_commits: Safety cap to avoid running forever on huge repos.

    Returns:
        List of findings representing historical placeholder swaps.
    """
    config = config or ScanConfig()

    try:
        import git
    except ImportError:
        logger.warning("GitPython not available; history analysis skipped.")
        return []

    try:
        repo = git.Repo(repo_root, search_parent_directories=True)
    except (git.InvalidGitRepositoryError, git.NoSuchPathError):
        logger.warning("Not a git repository: %s", repo_root)
        return []

    if repo.bare:
        logger.warning("Bare repository; history analysis skipped.")
        return []

    # ── Step 1: Collect commits (oldest first) ──────────────────────────
    try:
        commits = list(repo.iter_commits("--all", max_count=max_commits))
    except Exception as exc:
        logger.warning("Cannot iterate commits: %s", exc)
        return []

    commits.reverse()  # Oldest first for chronological timeline.

    # ── Step 2: Build per-(file, variable) timelines ────────────────────
    # timeline_key = (filepath_str, variable_name)
    # timeline_val = [LineageEvent, ...]
    timelines: dict[tuple[str, str], list[LineageEvent]] = {}

    for commit in commits:
        # Get the tree for this commit.
        try:
            tree = commit.tree
        except Exception:
            continue

        # Walk blobs in the tree (limit to scannable extensions).
        for blob in _walk_blobs(tree, config):
            filepath = Path(blob.path)

            try:
                content = blob.data_stream.read().decode("utf-8", errors="replace")
            except Exception:
                continue

            findings = scan_content(content, filepath, config)
            for f in findings:
                key = (f.file, f.variable)
                event = LineageEvent(
                    commit_sha=commit.hexsha[:12],
                    value=f.raw_value,
                    classification=classify_value(f.raw_value),
                )

                timeline = timelines.setdefault(key, [])
                # Only record if value changed from previous event.
                if not timeline or timeline[-1].value != event.value:
                    timeline.append(event)

    # ── Step 3: Detect placeholder → candidate transitions ──────────────
    lineage_findings: list[Finding] = []

    for (filepath, variable), events in timelines.items():
        for i in range(1, len(events)):
            prev = events[i - 1]
            curr = events[i]

            if placeholder_swap_detected(prev.value, curr.value):
                entropy = shannon_entropy(curr.value)
                if entropy < config.entropy_threshold:
                    continue  # Not high-entropy enough to flag.

                f = Finding(
                    file=filepath,
                    line_number=0,  # Historical — no line number.
                    variable=variable,
                    raw_value=curr.value,
                    entropy=entropy,
                    is_placeholder=False,
                    placeholder_swap=True,
                    commit_sha=curr.commit_sha,
                    reason=(
                        f"Placeholder-lineage swap in commit {curr.commit_sha}: "
                        f"'{prev.value[:20]}…' → high-entropy value "
                        f"(entropy {entropy:.2f} bits)"
                    ),
                )
                f.mask()
                lineage_findings.append(f)

    return lineage_findings


def _walk_blobs(tree, config: ScanConfig):
    """Recursively yield git blobs from *tree* that match scan extensions."""
    try:
        for item in tree.traverse():
            if item.type != "blob":
                continue
            path = Path(item.path)
            ext = path.suffix.lower()
            name = path.name
            if ext in config.scan_extensions or name in config.scan_filenames:
                yield item
    except Exception as exc:
        logger.debug("Error traversing tree: %s", exc)
