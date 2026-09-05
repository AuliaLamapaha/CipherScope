"""
CipherScope - decoders/atbash_decoder.py
Decodes (and encodes) Atbash cipher by mirroring the alphabet.
"""

from typing import NamedTuple


class DecodeResult(NamedTuple):
    success: bool
    output: str   # decoded text on success, error message on failure
    encoding: str # always "atbash" on success, or "" on failure


def decode_atbash(text: str) -> DecodeResult:
    """
    Apply Atbash cipher to the input string.

    Mapping: A<->Z, B<->Y, ... Z<->A (same for lowercase).
    Atbash is its own inverse: calling this function twice returns
    the original string. Non-alphabetic characters are unchanged.

    Handles:
    - Empty or whitespace-only input
    - Mixed alphabetic and non-alphabetic characters

    Args:
        text: The Atbash-ciphered (or plain) string to transform.

    Returns:
        DecodeResult(success, output, encoding).
        On failure, success=False, output holds the error reason.
    """
    if not text or not text.strip():
        return DecodeResult(False, "Input is empty.", "")

    result: list[str] = []
    for ch in text:
        if ch.isupper():
            result.append(chr(ord('Z') - (ord(ch) - ord('A'))))
        elif ch.islower():
            result.append(chr(ord('z') - (ord(ch) - ord('a'))))
        else:
            result.append(ch)

    return DecodeResult(True, "".join(result), "atbash")
