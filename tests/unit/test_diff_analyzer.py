"""Unit tests for secretguard.diff_analyzer."""

from __future__ import annotations

from pathlib import Path
import pytest
from secretguard.config import ScanConfig
from secretguard.diff_analyzer import enrich_with_diff, get_staged_files
from secretguard.scanner import Finding


class TestDiffAnalyzer:
    def test_get_staged_files_non_repo(self, tmp_path: Path) -> None:
        files = get_staged_files(tmp_path)
        assert files == []

    @pytest.mark.integration
    def test_enrich_with_diff_staged_swap(self, tmp_path: Path) -> None:
        import git

        repo = git.Repo.init(tmp_path)
        app_py = tmp_path / "app.py"

        # Commit 1: placeholder
        app_py.write_text('api_key = "YOUR_API_KEY_HERE"\n', encoding="utf-8")
        repo.index.add(["app.py"])
        repo.index.commit("initial commit")

        # Stage 2: real secret
        app_py.write_text('api_key = "aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s"\n', encoding="utf-8")

        finding = Finding(
            file=str(app_py),
            line_number=1,
            variable="api_key",
            raw_value="aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s",
        )

        enrich_with_diff([finding], tmp_path, ScanConfig())
        assert finding.placeholder_swap is True
