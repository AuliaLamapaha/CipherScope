"""
CipherScope - decoders/url_decoder.py
Decodes URL percent-encoded strings into human-readable text.
"""

import re
from urllib.parse import unquote
from typing import NamedTuple


class DecodeResult(NamedTuple):
    success: bool
    output: str   # decoded text on success, error message on failure
    encoding: str # text encoding used, e.g. "utf-8", or "" on failure


def _has_percent_encoding(text: str) -> bool:
    """Return True if text contains at least one valid percent-encoded sequence."""
    return bool(re.search(r"%[0-9a-fA-F]{2}", text))


def decode_url(text: str) -> DecodeResult:
    """
    Decode a URL percent-encoded string.

    Handles:
    - Empty or whitespace-only input
    - Strings with no percent-encoding (returned as-is with a note)
    - Invalid/incomplete percent sequences (passed through safely by urllib)
    - Non-UTF-8 percent-encoded bytes (falls back to latin-1)

    Args:
        text: The URL-encoded string to decode.

    Returns:
        DecodeResult(success, output, encoding).
        On failure, success=False, output holds the error reason.
    """
    if not text or not text.strip():
        return DecodeResult(False, "Input is empty.", "")

    stripped = text.strip()

    if not _has_percent_encoding(stripped):
        return DecodeResult(False, "No percent-encoded sequences found in input.", "")

    # Try UTF-8 first; if the result contains surrogates, fall back to latin-1
    decoded_utf8 = unquote(stripped, encoding="utf-8", errors="surrogateescape")

    try:
        # A clean UTF-8 decode produces no surrogates — verify round-trip
        decoded_utf8.encode("utf-8")
        decoded, encoding = decoded_utf8, "utf-8"
    except UnicodeEncodeError:
        decoded = unquote(stripped, encoding="latin-1", errors="replace")
        encoding = "latin-1"

    return DecodeResult(True, decoded, encoding)
