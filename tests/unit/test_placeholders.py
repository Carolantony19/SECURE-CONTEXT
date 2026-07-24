"""Unit tests for secretguard.placeholders."""

from __future__ import annotations

import pytest

from secretguard.placeholders import (
    classify_value,
    is_placeholder,
    placeholder_swap_detected,
)


class TestIsPlaceholder:
    """Test the placeholder detection library."""

    @pytest.mark.parametrize("value", [
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
        "TODO: add key here",
        "REMOVED",
        "CENSORED",
    ])
    def test_known_placeholders_detected(self, value: str) -> None:
        assert is_placeholder(value), f"Expected placeholder: {value}"

    @pytest.mark.parametrize("value", [
        "aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s",
        "sk-proj-aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s",
        "xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0sVdGkWn",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    ])
    def test_real_secrets_not_flagged_as_placeholder(self, value: str) -> None:
        assert not is_placeholder(value), f"Should NOT be placeholder: {value}"

    def test_extra_patterns(self) -> None:
        assert is_placeholder("CUSTOM_PATTERN_123", extra_patterns=[r"CUSTOM_\w+"])
        assert not is_placeholder("real_value_abc", extra_patterns=[r"CUSTOM_\w+"])

    def test_empty_string(self) -> None:
        assert not is_placeholder("")

    def test_whitespace_stripped(self) -> None:
        assert is_placeholder("  YOUR_API_KEY_HERE  ")

    def test_quoted_value(self) -> None:
        assert is_placeholder('"YOUR_API_KEY_HERE"')
        assert is_placeholder("'REPLACE_ME'")


class TestClassifyValue:
    """Test value classification."""

    def test_empty_string(self) -> None:
        assert classify_value("") == "empty"

    def test_placeholder(self) -> None:
        assert classify_value("YOUR_API_KEY_HERE") == "placeholder"

    def test_candidate(self) -> None:
        assert classify_value("aB3xK9mNpQ7rT2wU5yZ8cE1f") == "candidate"


class TestPlaceholderSwapDetected:
    """Test placeholder-swap behavioural signal."""

    def test_placeholder_to_real_value(self) -> None:
        assert placeholder_swap_detected(
            "YOUR_API_KEY_HERE",
            "aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s",
        )

    def test_placeholder_to_placeholder(self) -> None:
        assert not placeholder_swap_detected(
            "YOUR_API_KEY_HERE",
            "REPLACE_ME",
        )

    def test_real_to_real(self) -> None:
        assert not placeholder_swap_detected(
            "aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI",
            "xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0sVd",
        )

    def test_same_value(self) -> None:
        assert not placeholder_swap_detected(
            "YOUR_API_KEY_HERE",
            "YOUR_API_KEY_HERE",
        )

    def test_empty_old_value(self) -> None:
        assert not placeholder_swap_detected("", "some_new_value")

    def test_angle_bracket_placeholder_swap(self) -> None:
        assert placeholder_swap_detected(
            "<INSERT_TOKEN>",
            "aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s",
        )
