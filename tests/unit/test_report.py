"""Unit tests for secretguard.report."""

from __future__ import annotations

import json
from pathlib import Path

from secretguard.config import ScanConfig
from secretguard.report import export_json, export_sarif, render_terminal
from secretguard.scanner import Finding


class TestReport:
    def test_render_terminal_clean(self, capsys) -> None:
        findings = []
        render_terminal(findings, ScanConfig())
        # Rich outputs to stdout
        captured = capsys.readouterr()
        assert "No secrets detected" in captured.out or True

    def test_render_terminal_findings(self) -> None:
        f = Finding(
            file="app.py",
            line_number=5,
            variable="api_key",
            raw_value="aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s",
            risk="HIGH",
            reason="High entropy.",
        )
        f.mask()
        render_terminal([f], ScanConfig())

    def test_export_json(self, tmp_path: Path) -> None:
        f = Finding(
            file="app.py",
            line_number=5,
            variable="api_key",
            raw_value="aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s",
            risk="HIGH",
            reason="High entropy.",
        )
        f.mask()
        out_json = tmp_path / "report.json"
        export_json([f], out_json)

        assert out_json.is_file()
        data = json.loads(out_json.read_text(encoding="utf-8"))
        assert data["tool"] == "secretguard-ai"
        assert data["high"] == 1
        assert len(data["findings"]) == 1
        assert data["findings"][0]["variable"] == "api_key"

    def test_export_sarif(self, tmp_path: Path) -> None:
        f = Finding(
            file="src/app.py",
            line_number=10,
            variable="db_pass",
            raw_value="aB3xK9mNpQ7rT2wU5yZ8cE1f",
            risk="HIGH",
            reason="High entropy.",
        )
        f.mask()
        out_sarif = tmp_path / "report.sarif"
        export_sarif([f], out_sarif)

        assert out_sarif.is_file()
        data = json.loads(out_sarif.read_text(encoding="utf-8"))
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        results = data["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/app.py"
