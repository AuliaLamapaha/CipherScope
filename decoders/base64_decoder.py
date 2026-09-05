"""
CipherScope - decoders/base64_decoder.py
Decodes Base64-encoded strings into human-readable text.
"""

import base64
import binascii
import re
from typing import NamedTuple


class DecodeResult(NamedTuple):
    success: bool
    output: str   # decoded text on success, error message on failure
    encoding: str # detected text encoding, e.g. "utf-8", or "" on failure


def _pad(text: str) -> str:
    """Add missing Base64 padding characters ('=') if necessary."""
    remainder = len(text) % 4
    if remainder == 2:
        return text + "=="
    if remainder == 3:
        return text + "="
    return text


def _is_valid_base64_chars(text: str) -> bool:
    """Return True if text contains only valid Base64 characters."""
    return bool(re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", text))


def decode_base64(text: str) -> DecodeResult:
    """
    Decode a Base64-encoded string.

    Handles:
    - Missing padding (auto-corrected)
    - Invalid Base64 characters
    - Non-UTF-8 byte sequences (falls back to latin-1)
    - Empty or whitespace-only input

    Args:
        text: The Base64 string to decode.

    Returns:
        DecodeResult(success, output, encoding).
        On failure, success=False, output holds the error reason.
    """
    if not text or not text.strip():
        return DecodeResult(False, "Input is empty.", "")

    stripped = text.strip()

    if not _is_valid_base64_chars(stripped):
        return DecodeResult(False, "Input contains invalid Base64 characters.", "")

    padded = _pad(stripped)

    try:
        raw_bytes = base64.b64decode(padded, validate=True)
    except binascii.Error as exc:
        return DecodeResult(False, f"Base64 decoding failed: {exc}", "")

    # Attempt UTF-8 first, then fall back to latin-1 (never raises)
    try:
        decoded = raw_bytes.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        decoded = raw_bytes.decode("latin-1")
        encoding = "latin-1"

    return DecodeResult(True, decoded, encoding)
