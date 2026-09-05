"""
CipherScope - detectors/cipher_detector.py
Heuristic detection of classical cipher types from a string.
"""

import re
import codecs
from typing import NamedTuple

# Common English words used to score decoded candidates
_COMMON_WORDS = frozenset(
    "the and is in of to a it that was are be as at by he we do "
    "or an if so no up my me us go on "
    "hello world yes no hi ok now here there this with from".split()
)

# Expected frequency distribution of letters in English text (A-Z)
_EN_FREQ: dict[str, float] = {
    'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0,
    'n': 6.7,  's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3,
    'l': 4.0,  'c': 2.8, 'u': 2.8, 'm': 2.4, 'w': 2.4,
    'f': 2.2,  'g': 2.0, 'y': 2.0, 'p': 1.9, 'b': 1.5,
    'v': 1.0,  'k': 0.8, 'j': 0.2, 'x': 0.2, 'q': 0.1, 'z': 0.1,
}


class CipherCandidate(NamedTuple):
    cipher: str        # e.g. "ROT13", "Caesar (shift=7)", "Atbash"
    decoded: str       # best-guess decoded text
    confidence: str    # "High", "Medium", or "Low"


def _letter_only(text: str) -> str:
    """Return only lowercase alphabetic characters from text."""
    return "".join(ch.lower() for ch in text if ch.isalpha())


def _english_score(text: str) -> float:
    """
    Score how 'English-like' a string is using two signals:
    1. Chi-squared distance from expected English letter frequencies (lower = better).
    2. Fraction of tokens that are common English words (higher = better).
    Returns a combined score where higher means more English-like.
    """
    letters = _letter_only(text)
    if not letters:
        return 0.0

    total = len(letters)
    observed: dict[str, float] = {ch: letters.count(ch) / total * 100 for ch in _EN_FREQ}

    chi_sq = sum(
        ((observed.get(ch, 0) - expected) ** 2) / expected
        for ch, expected in _EN_FREQ.items()
    )

    tokens = re.findall(r"[a-zA-Z]+", text.lower())
    word_hits = sum(1 for t in tokens if t in _COMMON_WORDS)
    word_ratio = word_hits / len(tokens) if tokens else 0.0

    # Invert chi-sq so higher = more English-like; blend with word_ratio.
    # Weight word_ratio more heavily — it dominates for short inputs.
    return (1 / (1 + chi_sq)) * 0.4 + word_ratio * 0.6


def _confidence(score: float) -> str:
    """Map a numeric English score to a confidence label."""
    if score >= 0.40:
        return "High"
    if score >= 0.15:
        return "Medium"
    return "Low"


def _apply_atbash(text: str) -> str:
    """Apply Atbash transformation without importing decoders package."""
    result = []
    for ch in text:
        if ch.isupper():
            result.append(chr(ord('Z') - (ord(ch) - ord('A'))))
        elif ch.islower():
            result.append(chr(ord('z') - (ord(ch) - ord('a'))))
        else:
            result.append(ch)
    return "".join(result)


def _apply_caesar(text: str, shift: int) -> str:
    """Reverse a Caesar shift without importing decoders package."""
    result = []
    for ch in text:
        if ch.isupper():
            result.append(chr((ord(ch) - ord('A') - shift) % 26 + ord('A')))
        elif ch.islower():
            result.append(chr((ord(ch) - ord('a') - shift) % 26 + ord('a')))
        else:
            result.append(ch)
    return "".join(result)


def detect_cipher(text: str) -> list[CipherCandidate]:
    """
    Heuristically detect which classical cipher(s) a string might use.

    Evaluates ROT13, Atbash, and all 25 Caesar shifts by scoring how
    English-like each decoded candidate is. Returns candidates whose
    score exceeds a minimum threshold, sorted by confidence (best first).

    This function makes no guarantee of correctness — results are
    probabilistic heuristics.

    Args:
        text: The string to analyse.

    Returns:
        A list of CipherCandidate items. Empty list if input is invalid
        or no candidate scores above the minimum threshold.
    """
    if not text or not text.strip():
        return []

    if not _letter_only(text):
        return []

    candidates: list[tuple[float, CipherCandidate]] = []

    _THRESHOLD = 0.08

    # --- ROT13 (Caesar shift=13) ---
    rot13_decoded = codecs.decode(text, "rot_13")
    rot13_score = _english_score(rot13_decoded)
    if rot13_score > _THRESHOLD:
        candidates.append((rot13_score, CipherCandidate(
            "ROT13", rot13_decoded, _confidence(rot13_score)
        )))

    # --- Atbash ---
    atbash_decoded = _apply_atbash(text)
    atbash_score = _english_score(atbash_decoded)
    if atbash_score > _THRESHOLD:
        candidates.append((atbash_score, CipherCandidate(
            "Atbash", atbash_decoded, _confidence(atbash_score)
        )))

    # --- Caesar shifts 1–25 (skip 13 already covered by ROT13) ---
    for shift in range(1, 26):
        if shift == 13:
            continue
        decoded = _apply_caesar(text, shift)
        score = _english_score(decoded)
        if score > _THRESHOLD:
            candidates.append((score, CipherCandidate(
                f"Caesar (shift={shift})", decoded, _confidence(score)
            )))

    # Sort best score first, return only the CipherCandidate
    candidates.sort(key=lambda x: x[0], reverse=True)
    return [c for _, c in candidates]
