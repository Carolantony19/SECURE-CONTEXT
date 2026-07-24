"""Unit tests for secretguard.config."""

from __future__ import annotations

from pathlib import Path
from secretguard.config import ScanConfig


class TestConfig:
    def test_default_config(self) -> None:
        cfg = ScanConfig()
        assert cfg.entropy_threshold == 4.5
        assert ".py" in cfg.scan_extensions
        assert "Dockerfile" in cfg.scan_filenames
        assert cfg.parallel_workers == 4

    def test_from_toml(self, tmp_path: Path) -> None:
        toml_path = tmp_path / "secretguard.toml"
        toml_path.write_text(
            '[scan]\n'
            'entropy_threshold = 5.0\n'
            'extensions = [".py", ".env"]\n'
            'parallel_workers = 8\n'
            '\n'
            '[[rules]]\n'
            'id = "test-rule"\n'
            'pattern = "TEST_[A-Z0-9]+"\n'
            'severity = "HIGH"\n',
            encoding="utf-8",
        )

        cfg = ScanConfig.from_toml(toml_path)
        assert cfg.entropy_threshold == 5.0
        assert cfg.scan_extensions == {".py", ".env"}
        assert cfg.parallel_workers == 8
        assert len(cfg.custom_rules) == 1
        assert cfg.custom_rules[0].id == "test-rule"

    def test_load_auto_discover(self, tmp_path: Path) -> None:
        toml_path = tmp_path / "secretguard.toml"
        toml_path.write_text('[scan]\nentropy_threshold = 3.8\n', encoding="utf-8")

        cfg = ScanConfig.load(tmp_path)
        assert cfg.entropy_threshold == 3.8

    def test_load_missing_file_uses_defaults(self, tmp_path: Path) -> None:
        cfg = ScanConfig.load(tmp_path)
        assert cfg.entropy_threshold == 4.5
