"""Unit tests for secretguard.placeholders — placeholder detection & swap logic."""

from __future__ import annotations

import pytest

from secretguard.placeholders import (
    classify_value,
    is_placeholder,
    placeholder_swap_detected,
)


# ── is_placeholder ──────────────────────────────────────────────────────────


class TestIsPlaceholder:
    """Tests for the built-in placeholder pattern library."""

    @pytest.mark.parametrize(
        "value",
        [
            "YOUR_API_KEY_HERE",
            "YOUR-TOKEN-HERE",
            "<API_KEY>",
            "<INSERT_TOKEN>",
            "{SECRET}",
            "REPLACE_ME",
            "REPLACEME",
            "CHANGEME",
            "INSERT_KEY_HERE",
            "xxx",
            "xxxxxxxx",
            "example_key",
            "sample_token",
            "test_key",
            "dummy_secret",
            "fake_token",
            "placeholder",
            "default_key",
            "...",
            "****",
            "REDACTED",
            "sk-fake000000000000000000000000",
            "sk-test-abcdef1234567890",
        ],
    )
    def test_known_placeholders_detected(self, value: str):
        assert is_placeholder(value), f"Expected placeholder: {value!r}"

    @pytest.mark.parametrize(
        "value",
        [
            "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
            "sk-proj-aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s",
            "xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0sVdGkWn",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        ],
    )
    def test_real_secrets_not_flagged_as_placeholder(self, value: str):
        assert not is_placeholder(value), f"Should NOT be placeholder: {value!r}"

    def test_extra_patterns(self):
        """User-supplied extra patterns should be matched."""
        assert not is_placeholder("MY_CUSTOM_STUB")
        assert is_placeholder("MY_CUSTOM_STUB", extra_patterns=[r"MY_CUSTOM_\w+"])


# ── classify_value ──────────────────────────────────────────────────────────


class TestClassifyValue:
    def test_empty_string(self):
        assert classify_value("") == "empty"
        assert classify_value("   ") == "empty"

    def test_placeholder(self):
        assert classify_value("YOUR_API_KEY_HERE") == "placeholder"

    def test_candidate(self):
        assert classify_value("ghp_a1B2c3D4e5F6g7H8i9J0") == "candidate"

    def test_quoted_placeholder(self):
        """Surrounding quotes should be stripped before classification."""
        assert classify_value('"REPLACE_ME"') == "placeholder"
        assert classify_value("'YOUR_API_KEY_HERE'") == "placeholder"


# ── placeholder_swap_detected ───────────────────────────────────────────────


class TestPlaceholderSwapDetected:
    """Tests for the key behavioral detection signal."""

    def test_placeholder_to_real_value(self):
        """Classic swap: AI placeholder → real credential."""
        assert placeholder_swap_detected(
            old_value="YOUR_API_KEY_HERE",
            new_value="ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
        )

    def test_placeholder_to_placeholder(self):
        """Replacing one placeholder with another is NOT a swap."""
        assert not placeholder_swap_detected(
            old_value="YOUR_API_KEY_HERE",
            new_value="REPLACE_ME",
        )

    def test_real_to_real(self):
        """Changing one real value to another is NOT a swap
        (that's a rotation, not an AI-introduced leak)."""
        assert not placeholder_swap_detected(
            old_value="ghp_oldToken1234567890123456789012345",
            new_value="ghp_newToken9876543210987654321098765",
        )

    def test_same_value(self):
        """No change → no swap."""
        assert not placeholder_swap_detected(
            old_value="YOUR_API_KEY_HERE",
            new_value="YOUR_API_KEY_HERE",
        )

    def test_empty_old_value(self):
        """Empty old value is not a placeholder."""
        assert not placeholder_swap_detected(
            old_value="",
            new_value="ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
        )

    def test_angle_bracket_placeholder_swap(self):
        """<API_KEY> → real value."""
        assert placeholder_swap_detected(
            old_value="<API_KEY>",
            new_value="sk-proj-aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s",
        )
