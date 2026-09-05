"""
CipherScope - decoders/hex_decoder.py
Decodes hexadecimal strings into human-readable text.
"""

import re
from typing import NamedTuple


class DecodeResult(NamedTuple):
    success: bool
    output: str   # decoded text on success, error message on failure
    encoding: str # detected text encoding, e.g. "utf-8", or "" on failure


def _is_valid_hex(text: str) -> bool:
    """Return True if text contains only valid hexadecimal characters."""
    return bool(re.fullmatch(r"[0-9a-fA-F]+", text))


def decode_hex(text: str) -> DecodeResult:
    """
    Decode a hexadecimal string into text.

    Handles:
    - Empty or whitespace-only input
    - Non-hex characters
    - Odd-length hex strings (invalid byte boundary)
    - Non-UTF-8 byte sequences (falls back to latin-1)

    Args:
        text: The hexadecimal string to decode.

    Returns:
        DecodeResult(success, output, encoding).
        On failure, success=False, output holds the error reason.
    """
    if not text or not text.strip():
        return DecodeResult(False, "Input is empty.", "")

    stripped = text.strip()

    if not _is_valid_hex(stripped):
        return DecodeResult(False, "Input contains invalid hexadecimal characters.", "")

    if len(stripped) % 2 != 0:
        return DecodeResult(False, "Odd-length hex string: cannot align to byte boundary.", "")

    try:
        raw_bytes = bytes.fromhex(stripped)
    except ValueError as exc:
        return DecodeResult(False, f"Hex decoding failed: {exc}", "")

    # Attempt UTF-8 first, then fall back to latin-1 (never raises)
    try:
        decoded = raw_bytes.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        decoded = raw_bytes.decode("latin-1")
        encoding = "latin-1"

    return DecodeResult(True, decoded, encoding)
