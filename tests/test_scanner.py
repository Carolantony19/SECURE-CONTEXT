"""Unit tests for secretguard.scanner — regex-based secret detection."""

from __future__ import annotations

from pathlib import Path

import pytest

from secretguard.config import ScanConfig
from secretguard.scanner import Finding, scan_file


FIXTURES = Path(__file__).parent / "fixtures"


class TestScanFile:
    """Tests for the scan_file function."""

    def test_clean_file_finds_placeholders(self):
        """Clean file has assignments but values are placeholders / short."""
        findings = scan_file(FIXTURES / "clean_file.py")
        # The scanner finds regex matches; placeholder classification
        # happens in risk_scorer.  So we should still get some raw matches.
        # But very short values (< 8 chars) should be filtered out.
        for f in findings:
            assert len(f.raw_value) >= 8, (
                f"Short value should have been filtered: {f.raw_value!r}"
            )

    def test_leaky_file_finds_secrets(self):
        """Leaky file should produce multiple findings."""
        findings = scan_file(FIXTURES / "leaky_file.py")
        assert len(findings) >= 4, (
            f"Expected at least 4 findings, got {len(findings)}"
        )

    def test_leaky_file_captures_variable_names(self):
        """Variable names should be extracted correctly."""
        findings = scan_file(FIXTURES / "leaky_file.py")
        var_names = {f.variable for f in findings}
        # At least these should be captured:
        assert "api_key" in var_names
        assert "db_password" in var_names
        assert "github_token" in var_names

    def test_finding_has_line_number(self):
        """Each finding must have a positive line number."""
        findings = scan_file(FIXTURES / "leaky_file.py")
        for f in findings:
            assert f.line_number > 0

    def test_finding_mask(self):
        """Mask should reveal first N chars and replace the rest."""
        f = Finding(
            file="test.py",
            line_number=1,
            variable="key",
            raw_value="sk-proj-aB3xK9mNpQ7rT2wU5yZ8cE1",
        )
        masked = f.mask(reveal=6)
        assert masked.startswith("sk-pro")
        assert "***" not in masked[:6]
        assert "*" in masked[6:]

    def test_unsupported_extension_returns_empty(self):
        """Files with unsupported extensions should return no findings."""
        # Create a temporary file path (doesn't need to exist for this check)
        config = ScanConfig(scan_extensions={".py"})
        # Use a .md file — not in scan_extensions
        findings = scan_file(FIXTURES / "clean_file.py", config=ScanConfig(scan_extensions={".rs"}))
        assert findings == []

    def test_env_pattern_matching(self, tmp_path: Path):
        """Test .env file scanning with export syntax."""
        env_file = tmp_path / "test.env"
        env_file.write_text(
            'export API_KEY="sk-fake-aB3xK9mNpQ7rT2wU5yZ8cE1"\n'
            'DATABASE_PASSWORD=xK9mNpQ7rT2wU5yZ8cE1fH4jL\n'
            "# comment line\n"
        )
        findings = scan_file(env_file)
        assert len(findings) >= 1
        var_names = {f.variable for f in findings}
        assert "API_KEY" in var_names or "DATABASE_PASSWORD" in var_names

    def test_json_pattern_matching(self, tmp_path: Path):
        """Test JSON key-value scanning."""
        json_file = tmp_path / "config.json"
        json_file.write_text(
            '{\n'
            '  "api_key": "sk-fake-aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6o",\n'
            '  "name": "my-app"\n'
            '}\n'
        )
        findings = scan_file(json_file)
        assert len(findings) >= 1
        assert findings[0].variable == "api_key"

    def test_yaml_pattern_matching(self, tmp_path: Path):
        """Test YAML key-value scanning."""
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text(
            "api_key: sk-fake-aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0\n"
            "debug: true\n"
        )
        findings = scan_file(yaml_file)
        assert len(findings) >= 1
        assert findings[0].variable == "api_key"
