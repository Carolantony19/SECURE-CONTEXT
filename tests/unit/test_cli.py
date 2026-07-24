"""Unit tests for secretguard.cli."""

from __future__ import annotations

from pathlib import Path
from click.testing import CliRunner

from secretguard.cli import check, init, main, scan


class TestCLI:
    def test_cli_version(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "secretguard" in result.output

    def test_init_command(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(init)
            assert result.exit_code == 0
            assert Path(".gitignore").exists()
            assert Path(".secretguardignore").exists()

    def test_scan_clean_directory(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text('api_key = "YOUR_API_KEY_HERE"\n', encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(scan, [str(tmp_path)])
        assert result.exit_code == 0

    def test_scan_leaky_directory(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            'api_key = "aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0sVdGkWnXbCq"\n',
            encoding="utf-8",
        )
        runner = CliRunner()
        result = runner.invoke(scan, [str(tmp_path)])
        assert result.exit_code == 1

    def test_check_command_clean(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(check)
            assert result.exit_code == 0
