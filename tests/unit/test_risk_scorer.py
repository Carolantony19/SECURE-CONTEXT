"""Unit tests for secretguard.risk_scorer."""

from __future__ import annotations

from pathlib import Path
from secretguard.config import ScanConfig
from secretguard.risk_scorer import score_finding, score_findings
from secretguard.scanner import Finding


class TestRiskScorer:
    def test_score_placeholder_is_low(self) -> None:
        finding = Finding(
            file="app.py",
            line_number=1,
            variable="api_key",
            raw_value="YOUR_API_KEY_HERE",
        )
        score_finding(finding)
        assert finding.risk == "LOW"
        assert finding.is_placeholder is True

    def test_score_suppressed_by_allowlist(self) -> None:
        finding = Finding(
            file="tests/fixtures/app.py",
            line_number=1,
            variable="api_key",
            raw_value="aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s",
        )
        score_finding(finding, allowlist_patterns=["tests/fixtures/*"])
        assert finding.risk == "SUPPRESSED"

    def test_score_high_entropy_secret(self) -> None:
        finding = Finding(
            file="app.py",
            line_number=10,
            variable="secret_key",
            raw_value="aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0sVdGkWnXb",
        )
        score_finding(finding)
        assert finding.risk == "HIGH"

    def test_score_placeholder_swap_increases_score(self) -> None:
        finding = Finding(
            file="app.py",
            line_number=5,
            variable="token",
            raw_value="aB3xK9mNpQ7rT2wU5yZ8cE1f",
            placeholder_swap=True,
        )
        score_finding(finding)
        assert finding.risk in ("HIGH", "MEDIUM")
        assert "Placeholder-to-secret swap" in finding.reason

    def test_score_findings_batch(self, tmp_path: Path) -> None:
        ignore = tmp_path / ".secretguardignore"
        ignore.write_text("SUPPRESSED_VAR\n", encoding="utf-8")

        f1 = Finding(file="a.py", line_number=1, variable="SUPPRESSED_VAR", raw_value="aB3xK9mNpQ7rT2wU5yZ8cE1f")
        f2 = Finding(file="a.py", line_number=2, variable="REAL_VAR", raw_value="aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s")

        score_findings([f1, f2], repo_root=tmp_path)
        assert f1.risk == "SUPPRESSED"
        assert f2.risk == "HIGH"
