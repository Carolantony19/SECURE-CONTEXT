"""
Shannon entropy calculator for secret detection.

Shannon entropy measures the "randomness" or "information density" of a string.
It is the key quantitative signal that separates real credentials (high-entropy,
random-looking byte sequences) from English words, variable names, or
placeholder tokens (all low-entropy).

**Formula:**
    H(X) = -Σ p(x) · log₂(p(x))

where p(x) is the frequency of character x in the string, and the sum is over
all distinct characters.  The result is in *bits per character*.

**Interpretation for secret detection:**
    ┌──────────────────┬───────────────────────────────────────┐
    │ Entropy range    │ Typical content                       │
    ├──────────────────┼───────────────────────────────────────┤
    │ 0.0 – 2.0       │ Repeated chars, trivial strings       │
    │ 2.0 – 3.5       │ Simple English words, short names     │
    │ 3.5 – 4.5       │ Mixed prose, variable names           │
    │ 4.5 – 5.5       │ Base64-encoded data, hex tokens       │
    │ 5.5 – 6.5+      │ Cryptographic keys, random UUIDs      │
    └──────────────────┴───────────────────────────────────────┘

We default to a threshold of **4.5 bits**. Anything above that is suspicious.
"""

from __future__ import annotations

import math
import string
from collections import Counter


def shannon_entropy(value: str) -> float:
    """Compute Shannon entropy (bits per character) for *value*.

    Args:
        value: The string to measure.  An empty string returns 0.0.

    Returns:
        Entropy in bits, ranging from 0.0 (single repeated char) up to
        log₂(alphabet_size) for a perfectly uniform distribution.

    Examples:
        >>> round(shannon_entropy("aaaa"), 2)
        0.0
        >>> round(shannon_entropy("abcd"), 2)
        2.0
        >>> shannon_entropy("sk-fake000000000000000000000000") > 3.0
        True
    """
    if not value:
        return 0.0

    length = len(value)
    counts = Counter(value)

    # H = -Σ (count/n) * log₂(count/n)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def normalized_entropy(value: str) -> float:
    """Entropy normalized to [0, 1] based on the string's charset.

    Useful for comparing strings of different lengths and character sets.
    A value of 1.0 means every character appears with equal frequency
    (maximum randomness for the given alphabet).

    Args:
        value: The string to measure.

    Returns:
        Normalized entropy in [0.0, 1.0].
    """
    if len(value) <= 1:
        return 0.0

    raw = shannon_entropy(value)
    unique_chars = len(set(value))

    if unique_chars <= 1:
        return 0.0

    max_possible = math.log2(unique_chars)
    return raw / max_possible if max_possible > 0 else 0.0


def charset_bonus(value: str) -> float:
    """Return a bonus multiplier [1.0, 1.5] reflecting charset diversity.

    Real secrets tend to use multiple character classes (uppercase, lowercase,
    digits, symbols).  Placeholder tokens like ``YOUR_KEY_HERE`` typically
    use only uppercase + underscore.

    This bonus is multiplied into the composite risk score by
    :mod:`secretguard.risk_scorer`.
    """
    classes_present = 0
    if any(c in string.ascii_lowercase for c in value):
        classes_present += 1
    if any(c in string.ascii_uppercase for c in value):
        classes_present += 1
    if any(c in string.digits for c in value):
        classes_present += 1
    if any(c in string.punctuation for c in value):
        classes_present += 1

    # 1 class → 1.0,  2 → 1.15,  3 → 1.3,  4 → 1.5
    return 1.0 + 0.15 * max(0, classes_present - 1)


def is_high_entropy(value: str, threshold: float = 4.5) -> bool:
    """Quick predicate: is this value's entropy above *threshold*?

    Args:
        value:     String to test.
        threshold: Bits-per-character cutoff (default 4.5).

    Returns:
        True if ``shannon_entropy(value) >= threshold``.
    """
    return shannon_entropy(value) >= threshold
