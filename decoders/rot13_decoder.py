"""
CipherScope - decoders/rot13_decoder.py
Decodes (and encodes) ROT13-ciphered strings.
"""

import codecs
from typing import NamedTuple


class DecodeResult(NamedTuple):
    success: bool
    output: str   # decoded text on success, error message on failure
    encoding: str # always "rot13" on success, or "" on failure


def decode_rot13(text: str) -> DecodeResult:
    """
    Apply ROT13 to the input string.

    ROT13 is its own inverse: calling this function twice returns
    the original string. Non-alphabetic characters (digits, spaces,
    punctuation) are passed through unchanged.

    Handles:
    - Empty or whitespace-only input
    - Mixed alphabetic and non-alphabetic characters

    Args:
        text: The string to ROT13-decode (or encode).

    Returns:
        DecodeResult(success, output, encoding).
        On failure, success=False, output holds the error reason.
    """
    if not text or not text.strip():
        return DecodeResult(False, "Input is empty.", "")

    decoded = codecs.decode(text, "rot_13")
    return DecodeResult(True, decoded, "rot13")
