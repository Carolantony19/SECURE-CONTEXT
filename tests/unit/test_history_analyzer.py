"""Unit tests for secretguard.history_analyzer."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from secretguard.config import ScanConfig
from secretguard.history_analyzer import LineageEvent, analyze_history


class TestLineageEvent:
    """Tests for the LineageEvent data class."""

    def test_creation(self) -> None:
        event = LineageEvent(
            commit_sha="abc123", value="YOUR_API_KEY_HERE",
            classification="placeholder",
        )
        assert event.commit_sha == "abc123"
        assert event.classification == "placeholder"


class TestAnalyzeHistory:
    """Tests for the history analysis engine."""

    def test_non_git_repo_returns_empty(self, tmp_path: Path) -> None:
        """Should return empty list for a non-git directory."""
        findings = analyze_history(tmp_path, ScanConfig())
        assert findings == []

    def test_bare_repo_returns_empty(self, tmp_path: Path) -> None:
        """Should return empty list for a bare repo."""
        import git
        git.Repo.init(tmp_path, bare=True)
        findings = analyze_history(tmp_path, ScanConfig())
        assert findings == []

    @pytest.mark.integration
    def test_detects_placeholder_swap_in_history(self, tmp_path: Path) -> None:
        """Full integration: create commits with placeholder → secret swap."""
        import git

        repo = git.Repo.init(tmp_path)
        config_file = tmp_path / "config.py"

        # Commit 1: placeholder value
        config_file.write_text(
            'api_key = "YOUR_API_KEY_HERE"\n', encoding="utf-8"
        )
        repo.index.add(["config.py"])
        repo.index.commit("initial: placeholder")

        # Commit 2: replace placeholder with real-looking secret
        config_file.write_text(
            'api_key = "aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0sVdGkWnXb"\n',
            encoding="utf-8",
        )
        repo.index.add(["config.py"])
        repo.index.commit("feat: add real key")

        findings = analyze_history(tmp_path, ScanConfig(entropy_threshold=4.0))
        swap_findings = [f for f in findings if f.placeholder_swap]
        assert len(swap_findings) >= 1
        assert swap_findings[0].variable == "api_key"

    @pytest.mark.integration
    def test_no_false_positive_for_placeholder_to_placeholder(
        self, tmp_path: Path
    ) -> None:
        """Replacing one placeholder with another should NOT trigger."""
        import git

        repo = git.Repo.init(tmp_path)
        config_file = tmp_path / "config.py"

        config_file.write_text(
            'api_key = "YOUR_API_KEY_HERE"\n', encoding="utf-8"
        )
        repo.index.add(["config.py"])
        repo.index.commit("initial")

        config_file.write_text(
            'api_key = "REPLACE_ME"\n', encoding="utf-8"
        )
        repo.index.add(["config.py"])
        repo.index.commit("change placeholder")

        findings = analyze_history(tmp_path, ScanConfig(entropy_threshold=4.0))
        swap_findings = [f for f in findings if f.placeholder_swap]
        assert len(swap_findings) == 0
