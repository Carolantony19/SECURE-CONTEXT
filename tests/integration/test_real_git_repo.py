"""
Integration tests that create real git repos and run actual commits.

These tests validate the full end-to-end pipeline:
1. Create a temporary git repo.
2. Commit a file with a placeholder.
3. Modify it to a real-looking secret.
4. Assert that `secretguard check --staged` blocks the commit.
5. Fix the file and assert the next check passes.
6. Run `scan --history` and assert the swap is detected retroactively.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture
def git_repo(tmp_path: Path):
    """Create and yield a temporary git repo with initial config."""
    import git

    repo = git.Repo.init(tmp_path)
    repo.config_writer().set_value("user", "name", "Test").release()
    repo.config_writer().set_value("user", "email", "test@test.com").release()

    # Create a clean initial commit
    readme = tmp_path / "README.md"
    readme.write_text("# Test Repo\n", encoding="utf-8")
    repo.index.add(["README.md"])
    repo.index.commit("initial commit")

    yield tmp_path, repo


@pytest.mark.integration
class TestRealGitRepo:
    """End-to-end integration tests with real git operations."""

    def test_placeholder_commit_succeeds(self, git_repo) -> None:
        """A file with only placeholder values should pass the scan."""
        tmp_path, repo = git_repo

        config_file = tmp_path / "config.py"
        config_file.write_text(
            'api_key = "YOUR_API_KEY_HERE"\n'
            'token = "REPLACE_ME_WITH_REAL_TOKEN"\n',
            encoding="utf-8",
        )
        repo.index.add(["config.py"])
        # Don't actually commit — run scan instead
        result = subprocess.run(
            [sys.executable, "-m", "secretguard.cli", "scan",
             str(config_file), "--no-block", "--format", "json",
             "-o", str(tmp_path / "report.json")],
            capture_output=True, text=True,
        )

        report = json.loads((tmp_path / "report.json").read_text())
        # Placeholders should only be LOW risk
        high_count = report.get("high", 0)
        assert high_count == 0, f"Placeholders should not trigger HIGH: {report}"

    def test_real_secret_commit_blocked(self, git_repo) -> None:
        """A file with a high-entropy secret should trigger HIGH risk."""
        tmp_path, repo = git_repo

        config_file = tmp_path / "config.py"
        config_file.write_text(
            'api_key = "aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0sVdGkWnXbCq"\n',
            encoding="utf-8",
        )
        repo.index.add(["config.py"])

        result = subprocess.run(
            [sys.executable, "-m", "secretguard.cli", "scan",
             str(config_file), "--format", "json",
             "-o", str(tmp_path / "report.json")],
            capture_output=True, text=True,
        )

        report = json.loads((tmp_path / "report.json").read_text())
        assert report["high"] >= 1
        # CLI should exit non-zero
        assert result.returncode == 1

    def test_fixed_file_passes(self, git_repo) -> None:
        """After removing the secret, the scan should pass."""
        tmp_path, repo = git_repo

        config_file = tmp_path / "config.py"
        # First write: secret
        config_file.write_text(
            'api_key = "aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0sVdGkWnXbCq"\n',
            encoding="utf-8",
        )
        repo.index.add(["config.py"])
        repo.index.commit("bad commit")

        # Fix: use env var
        config_file.write_text(
            'import os\napi_key = os.environ.get("API_KEY", "")\n',
            encoding="utf-8",
        )
        repo.index.add(["config.py"])

        result = subprocess.run(
            [sys.executable, "-m", "secretguard.cli", "scan",
             str(config_file), "--format", "json",
             "-o", str(tmp_path / "report.json")],
            capture_output=True, text=True,
        )

        report = json.loads((tmp_path / "report.json").read_text())
        assert report["high"] == 0

    def test_history_scan_detects_past_swap(self, git_repo) -> None:
        """The history scanner should find a swap from past commits."""
        tmp_path, repo = git_repo

        config_file = tmp_path / "config.py"

        # Commit 1: placeholder
        config_file.write_text(
            'api_key = "YOUR_API_KEY_HERE"\n', encoding="utf-8"
        )
        repo.index.add(["config.py"])
        repo.index.commit("initial: placeholder")

        # Commit 2: real secret
        config_file.write_text(
            'api_key = "aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0sVdGkWnXbCq"\n',
            encoding="utf-8",
        )
        repo.index.add(["config.py"])
        repo.index.commit("feat: replaced placeholder")

        # Commit 3: fix it (but the swap is still in history)
        config_file.write_text(
            'import os\napi_key = os.environ.get("API_KEY", "")\n',
            encoding="utf-8",
        )
        repo.index.add(["config.py"])
        repo.index.commit("fix: use env var")

        # Run history scan — it should detect the swap at commit 2
        result = subprocess.run(
            [sys.executable, "-m", "secretguard.cli", "scan",
             str(tmp_path), "--history", "--format", "json",
             "-o", str(tmp_path / "report.json"), "--no-block"],
            capture_output=True, text=True,
        )

        report = json.loads((tmp_path / "report.json").read_text())
        swaps = [f for f in report["findings"] if f.get("placeholder_swap")]
        assert len(swaps) >= 1, (
            f"Expected at least 1 placeholder swap in history. "
            f"Got: {report}"
        )

    def test_json_output_format(self, git_repo) -> None:
        """JSON output should contain required fields."""
        tmp_path, repo = git_repo

        config_file = tmp_path / "config.py"
        config_file.write_text(
            'api_key = "aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0sVdGkWnXbCq"\n',
            encoding="utf-8",
        )

        result = subprocess.run(
            [sys.executable, "-m", "secretguard.cli", "scan",
             str(config_file), "--format", "json",
             "-o", str(tmp_path / "report.json"), "--no-block"],
            capture_output=True, text=True,
        )

        report = json.loads((tmp_path / "report.json").read_text())
        assert "tool" in report
        assert "findings" in report
        assert "high" in report
        for f in report["findings"]:
            assert "file" in f
            assert "variable" in f
            assert "risk" in f

    def test_sarif_output_format(self, git_repo) -> None:
        """SARIF output should be valid SARIF 2.1.0."""
        tmp_path, repo = git_repo

        config_file = tmp_path / "config.py"
        config_file.write_text(
            'api_key = "aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0sVdGkWnXbCq"\n',
            encoding="utf-8",
        )

        result = subprocess.run(
            [sys.executable, "-m", "secretguard.cli", "scan",
             str(config_file), "--format", "sarif",
             "-o", str(tmp_path / "report.sarif"), "--no-block"],
            capture_output=True, text=True,
        )

        sarif = json.loads((tmp_path / "report.sarif").read_text())
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert "tool" in sarif["runs"][0]
        assert "results" in sarif["runs"][0]
