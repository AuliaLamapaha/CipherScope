"""
CipherScope - detector.py
Detects the probable encoding/cipher/hash type of a given string.
"""

import re
import base64
import binascii
import codecs
from typing import NamedTuple


class DetectionResult(NamedTuple):
    type: str
    confidence: str  # "High", "Medium", "Low"


# Known hash lengths mapped to algorithm names
_HASH_LENGTHS: dict[int, str] = {
    32:  "MD5",
    40:  "SHA-1",
    56:  "SHA-224",
    64:  "SHA-256",
    96:  "SHA-384",
    128: "SHA-512",
}


def _is_hex(text: str) -> bool:
    """Return True if text is a valid hexadecimal string."""
    return bool(re.fullmatch(r"[0-9a-fA-F]+", text))


def _is_base64(text: str) -> bool:
    """Return True if text looks like valid Base64-encoded data."""
    pattern = r"^[A-Za-z0-9+/]*={0,2}$"
    if not re.fullmatch(pattern, text):
        return False
    if len(text) % 4 != 0:
        return False
    try:
        base64.b64decode(text, validate=True)
        return True
    except (binascii.Error, ValueError):
        return False


def _is_url_encoded(text: str) -> bool:
    """Return True if text contains URL-encoded sequences."""
    return bool(re.search(r"%[0-9a-fA-F]{2}", text))


def _is_rot13(text: str) -> bool:
    """
    Heuristic: text is likely ROT13 if it contains only ASCII letters/spaces
    and its ROT13-decoded form contains common English letter patterns.
    """
    if not re.fullmatch(r"[A-Za-z\s.,!?'-]+", text):
        return False
    decoded = codecs.decode(text, "rot_13")
    common = re.compile(r"\b(the|and|is|in|of|to|a|it|that|was)\b", re.I)
    return bool(common.search(decoded))


def detect_type(text: str) -> DetectionResult:
    """
    Detect the probable type of the given input string.

    Args:
        text: The string to analyse. Empty strings return Unknown/Low.

    Returns:
        A DetectionResult with (type, confidence).
    """
    if not text or not text.strip():
        return DetectionResult("Unknown", "Low")

    stripped = text.strip()

    if _is_url_encoded(stripped):
        return DetectionResult("URL Encoding", "High")

    if _is_hex(stripped):
        algo = _HASH_LENGTHS.get(len(stripped))
        if algo:
            return DetectionResult(f"Hash ({algo})", "High")
        return DetectionResult("Hexadecimal", "Medium")

    if _is_base64(stripped):
        return DetectionResult("Base64", "Medium")

    if _is_rot13(stripped):
        return DetectionResult("ROT13", "Low")

    return DetectionResult("Unknown", "Low")
