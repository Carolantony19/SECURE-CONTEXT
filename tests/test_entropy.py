"""Unit tests for secretguard.entropy — Shannon entropy calculations."""

from __future__ import annotations

import math

import pytest

from secretguard.entropy import (
    charset_bonus,
    is_high_entropy,
    normalized_entropy,
    shannon_entropy,
)


# ── shannon_entropy ─────────────────────────────────────────────────────────


class TestShannonEntropy:
    """Core entropy calculation tests."""

    def test_empty_string_returns_zero(self):
        assert shannon_entropy("") == 0.0

    def test_single_char_returns_zero(self):
        """A string of identical characters has zero entropy."""
        assert shannon_entropy("aaaa") == 0.0
        assert shannon_entropy("ZZZZZZZZZ") == 0.0

    def test_two_equally_distributed_chars(self):
        """'abab' → exactly 1.0 bit (two equally likely symbols)."""
        assert math.isclose(shannon_entropy("abab"), 1.0, abs_tol=1e-9)

    def test_four_equally_distributed_chars(self):
        """'abcd' → exactly 2.0 bits."""
        assert math.isclose(shannon_entropy("abcd"), 2.0, abs_tol=1e-9)

    def test_real_secret_has_high_entropy(self):
        """A base64-like secret should have entropy > 4.5 bits."""
        secret = "sk-proj-aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s"
        assert shannon_entropy(secret) > 4.5

    def test_english_word_has_low_entropy(self):
        """A simple English word should have entropy < 4.0 bits."""
        assert shannon_entropy("password") < 4.0
        assert shannon_entropy("hello") < 3.5

    def test_placeholder_has_moderate_entropy(self):
        """YOUR_API_KEY_HERE has moderate entropy (mix of uppercase + underscore)."""
        entropy = shannon_entropy("YOUR_API_KEY_HERE")
        assert 2.5 < entropy < 4.5

    def test_hex_string_has_high_entropy(self):
        """A 32-char hex string should have entropy ≈ 4.0 bits."""
        hex_str = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        assert shannon_entropy(hex_str) > 3.5


# ── normalized_entropy ──────────────────────────────────────────────────────


class TestNormalizedEntropy:
    def test_empty_returns_zero(self):
        assert normalized_entropy("") == 0.0

    def test_single_char_returns_zero(self):
        assert normalized_entropy("a") == 0.0

    def test_uniform_distribution_returns_one(self):
        """If all characters appear equally, normalized entropy = 1.0."""
        assert math.isclose(normalized_entropy("abcd"), 1.0, abs_tol=1e-9)

    def test_skewed_distribution_below_one(self):
        """'aaab' is less random than 'abcd'."""
        assert normalized_entropy("aaab") < 1.0


# ── charset_bonus ───────────────────────────────────────────────────────────


class TestCharsetBonus:
    def test_single_class_no_bonus(self):
        assert charset_bonus("abcdef") == 1.0

    def test_two_classes(self):
        """Lowercase + digits → 1.15 bonus."""
        assert math.isclose(charset_bonus("abc123"), 1.15, abs_tol=1e-9)

    def test_three_classes(self):
        """Lowercase + uppercase + digits → 1.3."""
        assert math.isclose(charset_bonus("aA1"), 1.3, abs_tol=1e-9)

    def test_four_classes(self):
        """All four classes → 1.45 bonus."""
        assert math.isclose(charset_bonus("aA1!"), 1.45, abs_tol=1e-9)


# ── is_high_entropy ─────────────────────────────────────────────────────────


class TestIsHighEntropy:
    def test_high_entropy_true(self):
        secret = "sk-proj-aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s"
        assert is_high_entropy(secret, threshold=4.5) is True

    def test_low_entropy_false(self):
        assert is_high_entropy("password", threshold=4.5) is False

    def test_custom_threshold(self):
        """With a very low threshold, even 'abcd' qualifies."""
        assert is_high_entropy("abcd", threshold=1.5) is True
