"""
Composite risk scorer for SecretGuard AI findings.

Combines entropy, charset diversity, file-type weight, placeholder-swap/lineage,
and allowlist filtering into a single HIGH/MEDIUM/LOW label.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from secretguard.allowlist import is_allowed, load_allowlist
from secretguard.config import ScanConfig
from secretguard.entropy import charset_bonus, shannon_entropy
from secretguard.placeholders import is_placeholder
from secretguard.scanner import Finding

HIGH_THRESHOLD: float = 7.0
MEDIUM_THRESHOLD: float = 5.0
SWAP_BONUS: float = 2.0

_FILE_WEIGHTS: dict[str, float] = {
    ".env": 1.5, ".py": 1.2, ".js": 1.2, ".ts": 1.2,
    ".tf": 1.3, ".yaml": 1.1, ".yml": 1.1,
    ".json": 1.0, ".toml": 1.0, ".cfg": 1.1, ".ini": 1.1,
}


def score_finding(
    finding: Finding,
    config: Optional[ScanConfig] = None,
    allowlist_patterns: Optional[list[str]] = None,
) -> Finding:
    """Compute and assign a composite risk label to *finding*."""
    config = config or ScanConfig()
    allowlist_patterns = allowlist_patterns or []

    # ── Allowlist check ─────────────────────────────────────────────────
    if allowlist_patterns and is_allowed(
        filepath=finding.file,
        variable=finding.variable,
        raw_value=finding.raw_value,
        patterns=allowlist_patterns,
    ):
        finding.risk = "SUPPRESSED"
        finding.reason = "Suppressed by allowlist."
        return finding

    # ── Entropy ─────────────────────────────────────────────────────────
    finding.entropy = shannon_entropy(finding.raw_value)

    # ── Placeholder check ───────────────────────────────────────────────
    finding.is_placeholder = is_placeholder(
        finding.raw_value, extra_patterns=config.extra_placeholder_patterns
    )

    if finding.is_placeholder:
        finding.risk = "LOW"
        finding.reason = "Value matches a known placeholder pattern."
        return finding

    # ── Composite score ─────────────────────────────────────────────────
    cb = charset_bonus(finding.raw_value)
    ext = Path(finding.file).suffix.lower()
    fw = _FILE_WEIGHTS.get(ext, 1.0)
    # Dockerfile has no extension — use .env weight
    if Path(finding.file).name == "Dockerfile":
        fw = 1.4

    raw_score = finding.entropy * cb * fw

    if finding.placeholder_swap:
        raw_score += SWAP_BONUS

    # ── Label mapping ───────────────────────────────────────────────────
    if raw_score >= HIGH_THRESHOLD:
        finding.risk = "HIGH"
        reasons = [f"High entropy ({finding.entropy:.2f} bits)"]
        if finding.placeholder_swap:
            reasons.append("Placeholder-to-secret swap detected")
        if fw > 1.0:
            reasons.append(f"Sensitive file type ({ext or Path(finding.file).name})")
        if finding.commit_sha:
            reasons.append(f"Historical swap at {finding.commit_sha}")
        finding.reason = "; ".join(reasons) + "."
    elif raw_score >= MEDIUM_THRESHOLD:
        finding.risk = "MEDIUM"
        finding.reason = (
            f"Moderate entropy ({finding.entropy:.2f} bits); review recommended."
        )
    else:
        finding.risk = "LOW"
        finding.reason = f"Low composite score ({raw_score:.2f})."

    return finding


def score_findings(
    findings: list[Finding],
    config: Optional[ScanConfig] = None,
    repo_root: Optional[Path] = None,
) -> list[Finding]:
    """Score a batch of findings, loading allowlist from *repo_root*."""
    config = config or ScanConfig()
    allowlist = []
    if repo_root:
        allowlist = load_allowlist(repo_root)
        # Also merge config-level allowlist paths
        allowlist.extend(config.allowlist_paths)

    for finding in findings:
        score_finding(finding, config, allowlist)
    return findings
