"""Unit tests for secretguard.allowlist."""

from __future__ import annotations

from pathlib import Path
import hashlib
from secretguard.allowlist import is_allowed, load_allowlist


class TestAllowlist:
    def test_load_allowlist(self, tmp_path: Path) -> None:
        ignore_file = tmp_path / ".secretguardignore"
        ignore_file.write_text(
            "# Comment line\n"
            "tests/fixtures/*\n"
            "\n"
            "EXAMPLE_KEY\n"
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n",
            encoding="utf-8",
        )

        patterns = load_allowlist(tmp_path)
        assert len(patterns) == 3
        assert "tests/fixtures/*" in patterns
        assert "EXAMPLE_KEY" in patterns

    def test_load_allowlist_missing_file(self, tmp_path: Path) -> None:
        patterns = load_allowlist(tmp_path)
        assert patterns == []

    def test_is_allowed_variable_match(self) -> None:
        patterns = ["EXAMPLE_KEY", "OTHER_VAR"]
        assert is_allowed(
            filepath="src/app.py",
            variable="EXAMPLE_KEY",
            raw_value="some_val_12345",
            patterns=patterns,
        )
        assert is_allowed(
            filepath="src/app.py",
            variable="example_key",  # case insensitive
            raw_value="some_val_12345",
            patterns=patterns,
        )
        assert not is_allowed(
            filepath="src/app.py",
            variable="REAL_SECRET",
            raw_value="some_val_12345",
            patterns=patterns,
        )

    def test_is_allowed_glob_match(self) -> None:
        patterns = ["tests/fixtures/*", "src/vendor/*.py"]
        assert is_allowed(
            filepath="tests/fixtures/leaky.py",
            variable="SECRET",
            raw_value="val12345",
            patterns=patterns,
        )
        assert is_allowed(
            filepath="src/vendor/lib.py",
            variable="SECRET",
            raw_value="val12345",
            patterns=patterns,
        )
        assert not is_allowed(
            filepath="src/main.py",
            variable="SECRET",
            raw_value="val12345",
            patterns=patterns,
        )

    def test_is_allowed_hash_match(self) -> None:
        val = "secret_val_to_hash_12345"
        val_hash = hashlib.sha256(val.encode("utf-8")).hexdigest()
        patterns = [f"sha256:{val_hash}"]

        assert is_allowed(
            filepath="src/app.py",
            variable="ANY_VAR",
            raw_value=val,
            patterns=patterns,
        )
        assert not is_allowed(
            filepath="src/app.py",
            variable="ANY_VAR",
            raw_value="other_val_12345",
            patterns=patterns,
        )
