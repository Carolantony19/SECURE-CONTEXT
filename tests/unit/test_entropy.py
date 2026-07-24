"""Unit tests for secretguard.entropy."""

from __future__ import annotations

import pytest

from secretguard.entropy import (
    charset_bonus,
    is_high_entropy,
    normalized_entropy,
    shannon_entropy,
)


class TestShannonEntropy:
    """Tests for the core entropy calculation."""

    def test_empty_string_returns_zero(self) -> None:
        assert shannon_entropy("") == 0.0

    def test_single_char_returns_zero(self) -> None:
        assert shannon_entropy("a") == 0.0

    def test_repeated_chars(self) -> None:
        assert shannon_entropy("aaaaaaaaaa") == 0.0

    def test_two_equally_distributed_chars(self) -> None:
        result = shannon_entropy("ab")
        assert abs(result - 1.0) < 0.001

    def test_four_equally_distributed_chars(self) -> None:
        result = shannon_entropy("abcd")
        assert abs(result - 2.0) < 0.001

    def test_real_secret_has_high_entropy(self) -> None:
        secret = "aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s"
        assert shannon_entropy(secret) > 4.5

    def test_english_word_has_low_entropy(self) -> None:
        assert shannon_entropy("password") < 3.5

    def test_placeholder_has_moderate_entropy(self) -> None:
        result = shannon_entropy("YOUR_API_KEY_HERE")
        assert 2.0 < result < 4.0

    def test_hex_string_has_high_entropy(self) -> None:
        assert shannon_entropy("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6") > 3.5

    def test_non_ascii_handles_correctly(self) -> None:
        """Non-ASCII characters should not crash the function."""
        result = shannon_entropy("pässwörd_üñíçödé")
        assert result > 0

    def test_very_long_string(self) -> None:
        """Long strings should be handled without error."""
        result = shannon_entropy("x" * 100_000)
        assert result == 0.0


class TestNormalizedEntropy:
    """Tests for normalized entropy (0-1 range)."""

    def test_empty_returns_zero(self) -> None:
        assert normalized_entropy("") == 0.0

    def test_single_char_returns_zero(self) -> None:
        assert normalized_entropy("a") == 0.0

    def test_uniform_distribution_returns_one(self) -> None:
        result = normalized_entropy("abcdefghijklmnop")
        assert abs(result - 1.0) < 0.001

    def test_skewed_distribution_below_one(self) -> None:
        result = normalized_entropy("aaaaab")
        assert 0.0 < result < 1.0


class TestCharsetBonus:
    """Tests for character-set diversity bonus."""

    def test_single_class_no_bonus(self) -> None:
        assert charset_bonus("abcdefgh") == 1.0

    def test_two_classes(self) -> None:
        assert abs(charset_bonus("abcDEF") - 1.15) < 0.001

    def test_three_classes(self) -> None:
        assert abs(charset_bonus("abcDEF123") - 1.3) < 0.001

    def test_four_classes(self) -> None:
        result = charset_bonus("aB1!")
        assert abs(result - 1.45) < 0.001  # 1.0 + 0.15 * 3

    def test_empty_string(self) -> None:
        result = charset_bonus("")
        assert result == 1.0


class TestIsHighEntropy:
    """Tests for the high-entropy predicate."""

    def test_high_entropy_true(self) -> None:
        assert is_high_entropy("aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s")

    def test_low_entropy_false(self) -> None:
        assert not is_high_entropy("password")

    def test_custom_threshold(self) -> None:
        value = "abcdefghij"
        entropy = shannon_entropy(value)
        assert is_high_entropy(value, threshold=entropy - 0.1)
        assert not is_high_entropy(value, threshold=entropy + 0.1)

    def test_empty_string_false(self) -> None:
        assert not is_high_entropy("")
