"""
CipherScope - decoders/caesar_decoder.py
Decodes Caesar cipher by reversing an alphabetic shift.
"""

from typing import NamedTuple


class DecodeResult(NamedTuple):
    success: bool
    output: str   # decoded text on success, error message on failure
    encoding: str # e.g. "caesar-shift-3", or "" on failure


def decode_caesar(text: str, shift: int) -> DecodeResult:
    """
    Decode a Caesar-ciphered string by reversing the given shift.

    Only A-Z and a-z are shifted; digits, spaces, punctuation, and
    all other characters are passed through unchanged.

    Args:
        text:  The ciphered string to decode.
        shift: Number of positions to reverse (0–25).

    Returns:
        DecodeResult(success, output, encoding).
        On failure, success=False, output holds the error reason.
    """
    if not text or not text.strip():
        return DecodeResult(False, "Input is empty.", "")

    if not isinstance(shift, int) or isinstance(shift, bool):
        return DecodeResult(False, "Shift must be an integer.", "")

    if not (0 <= shift <= 25):
        return DecodeResult(False, f"Shift {shift} is out of range (0–25).", "")

    result: list[str] = []
    for ch in text:
        if ch.isupper():
            result.append(chr((ord(ch) - ord('A') - shift) % 26 + ord('A')))
        elif ch.islower():
            result.append(chr((ord(ch) - ord('a') - shift) % 26 + ord('a')))
        else:
            result.append(ch)

    return DecodeResult(True, "".join(result), f"caesar-shift-{shift}")
