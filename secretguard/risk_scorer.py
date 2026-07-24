"""
Composite risk scorer for SecretGuard-AI findings.

Combines four orthogonal signals into a single **risk label**
(``HIGH``, ``MEDIUM``, or ``LOW``) per finding:

1. **Entropy** — Shannon entropy of the raw value.
2. **Charset diversity** — bonus from mixed character classes.
3. **File-type weight** — ``.env`` files are riskier than ``.json``.
4. **Placeholder-swap flag** — behavioral signal from diff analysis.

Scoring formula
───────────────
    raw_score  = entropy × charset_bonus × file_weight
    if placeholder_swap:
        raw_score += SWAP_BONUS          # +2.0 — strong behavioral signal

    Label mapping:
        raw_score ≥ HIGH_THRESHOLD  →  HIGH   (blocks commit)
        raw_score ≥ MED_THRESHOLD   →  MEDIUM (warning)
        else                        →  LOW    (informational)

The thresholds are chosen so that:
- A base64 secret in a ``.env`` file  →  HIGH  (entropy ≈ 5.5, bonus ~1.3, weight 1.5 → ~10.7)
- A placeholder swap to high-entropy  →  HIGH  (swap bonus alone pushes it over)
- An English-word "password" in YAML  →  LOW   (entropy ≈ 3.5 → ~5.2)
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from secretguard.config import ScanConfig
from secretguard.entropy import shannon_entropy, charset_bonus, is_high_entropy
from secretguard.placeholders import is_placeholder
from secretguard.scanner import Finding


# ── Thresholds ──────────────────────────────────────────────────────────────

HIGH_THRESHOLD: float = 7.0
MEDIUM_THRESHOLD: float = 5.0
SWAP_BONUS: float = 2.0          # Flat bonus when a placeholder swap is detected.

# File-extension risk weights.  Higher = riskier environment.
_FILE_WEIGHTS: dict[str, float] = {
    ".env":  1.5,   # Environment files are the most dangerous — often loaded at runtime.
    ".py":   1.2,
    ".js":   1.2,
    ".ts":   1.2,
    ".yaml": 1.1,
    ".yml":  1.1,
    ".json": 1.0,
    ".toml": 1.0,
    ".cfg":  1.1,
    ".ini":  1.1,
}


def score_finding(finding: Finding, config: Optional[ScanConfig] = None) -> Finding:
    """Compute and assign a composite risk label to *finding*.

    Mutates the finding in place (sets ``.entropy``, ``.is_placeholder``,
    ``.risk``, and ``.reason``).

    Args:
        finding: A :class:`~secretguard.scanner.Finding` from the scanner.
        config:  Optional configuration for threshold overrides.

    Returns:
        The same finding, enriched with risk data.
    """
    config = config or ScanConfig()

    # ── Step 1: Entropy ─────────────────────────────────────────────────
    finding.entropy = shannon_entropy(finding.raw_value)

    # ── Step 2: Placeholder check ───────────────────────────────────────
    finding.is_placeholder = is_placeholder(
        finding.raw_value, extra_patterns=config.extra_placeholder_patterns
    )

    if finding.is_placeholder:
        finding.risk = "LOW"
        finding.reason = "Value matches a known placeholder pattern."
        return finding

    # ── Step 3: Composite score ─────────────────────────────────────────
    cb = charset_bonus(finding.raw_value)
    ext = Path(finding.file).suffix.lower()
    fw = _FILE_WEIGHTS.get(ext, 1.0)

    raw_score = finding.entropy * cb * fw

    if finding.placeholder_swap:
        raw_score += SWAP_BONUS

    # ── Step 4: Label mapping ───────────────────────────────────────────
    if raw_score >= HIGH_THRESHOLD:
        finding.risk = "HIGH"
        reasons = [f"High entropy ({finding.entropy:.2f} bits)"]
        if finding.placeholder_swap:
            reasons.append("Placeholder-to-secret swap detected")
        if fw > 1.0:
            reasons.append(f"Sensitive file type ({ext})")
        finding.reason = "; ".join(reasons) + "."
    elif raw_score >= MEDIUM_THRESHOLD:
        finding.risk = "MEDIUM"
        finding.reason = (
            f"Moderate entropy ({finding.entropy:.2f} bits); "
            f"review recommended."
        )
    else:
        finding.risk = "LOW"
        finding.reason = f"Low composite score ({raw_score:.2f})."

    return finding


def score_findings(
    findings: list[Finding],
    config: Optional[ScanConfig] = None,
) -> list[Finding]:
    """Score a batch of findings.

    Convenience wrapper that calls :func:`score_finding` on each element.
    """
    for finding in findings:
        score_finding(finding, config)
    return findings
