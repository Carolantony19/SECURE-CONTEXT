"""Unit tests for secretguard.scanner."""

from __future__ import annotations

import os
from pathlib import Path
from textwrap import dedent

import pytest

from secretguard.config import ScanConfig
from secretguard.scanner import Finding, scan_content, scan_file


@pytest.fixture
def config() -> ScanConfig:
    return ScanConfig()


class TestScanContent:
    """Tests for the inner scan_content function."""

    def test_py_assignment(self, config: ScanConfig) -> None:
        content = 'api_key = "aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s"'
        findings = scan_content(content, Path("app.py"), config)
        assert len(findings) >= 1
        assert findings[0].variable == "api_key"

    def test_env_assignment(self, config: ScanConfig) -> None:
        content = 'SECRET_TOKEN=aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s'
        findings = scan_content(content, Path(".env"), config)
        assert len(findings) >= 1

    def test_json_key_value(self, config: ScanConfig) -> None:
        content = '{"api_key": "aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s"}'
        findings = scan_content(content, Path("config.json"), config)
        assert len(findings) >= 1

    def test_yaml_key_value(self, config: ScanConfig) -> None:
        content = "api_key: aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s"
        findings = scan_content(content, Path("config.yaml"), config)
        assert len(findings) >= 1

    def test_dockerfile_env(self, config: ScanConfig) -> None:
        content = "ENV API_KEY=aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s"
        findings = scan_content(content, Path("Dockerfile"), config)
        assert len(findings) >= 1

    def test_terraform_assignment(self, config: ScanConfig) -> None:
        content = 'secret_key = "aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s"'
        findings = scan_content(content, Path("main.tf"), config)
        assert len(findings) >= 1

    def test_short_values_skipped(self, config: ScanConfig) -> None:
        content = 'api_key = "short"'
        findings = scan_content(content, Path("app.py"), config)
        assert len(findings) == 0

    def test_line_numbers_are_correct(self, config: ScanConfig) -> None:
        content = 'line1\napi_key = "aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL"'
        findings = scan_content(content, Path("app.py"), config)
        assert findings[0].line_number == 2

    def test_masking(self, config: ScanConfig) -> None:
        content = 'api_key = "aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s"'
        findings = scan_content(content, Path("app.py"), config)
        assert findings[0].masked_value.startswith("aB3xK9")
        assert "****" in findings[0].masked_value or "***" in findings[0].masked_value

    def test_multiple_findings_in_file(self, config: ScanConfig) -> None:
        content = dedent("""\
            api_key = "aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s"
            password = "xK9mNpQ7rT2wU5yZ8cE1fH4jL"
        """)
        findings = scan_content(content, Path("app.py"), config)
        assert len(findings) >= 2


class TestScanFile:
    """Tests for file-level scanning with filesystem guards."""

    def test_scan_real_file(self, tmp_path: Path, config: ScanConfig) -> None:
        f = tmp_path / "app.py"
        f.write_text('api_key = "aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s"\n')
        findings = scan_file(f, config)
        assert len(findings) >= 1

    def test_unsupported_extension_returns_empty(
        self, tmp_path: Path, config: ScanConfig
    ) -> None:
        f = tmp_path / "image.png"
        f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        findings = scan_file(f, config)
        assert findings == []

    def test_binary_file_skipped(self, tmp_path: Path, config: ScanConfig) -> None:
        f = tmp_path / "data.py"
        f.write_bytes(b"api_key = 'test'\x00\x00\x00binary junk")
        findings = scan_file(f, config)
        assert findings == []

    def test_large_file_skipped(self, tmp_path: Path, config: ScanConfig) -> None:
        f = tmp_path / "huge.py"
        f.write_text("x" * (config.max_file_size + 1))
        findings = scan_file(f, config)
        assert findings == []

    def test_empty_file(self, tmp_path: Path, config: ScanConfig) -> None:
        f = tmp_path / "empty.py"
        f.write_text("")
        findings = scan_file(f, config)
        assert findings == []

    def test_non_utf8_file(self, tmp_path: Path, config: ScanConfig) -> None:
        """Non-UTF-8 files should be read with latin-1 fallback, not crash."""
        f = tmp_path / "latin.py"
        content = 'api_key = "café_secret_value_here_123"\n'.encode("latin-1")
        f.write_bytes(content)
        findings = scan_file(f, config)
        # Should not crash; may or may not find a match depending on encoding
        assert isinstance(findings, list)
