"""
CipherScope - utils/validators.py
Shared input validation helpers used across the CipherScope modules.
"""

import re
import base64
import binascii


def is_empty(text: str) -> bool:
    """Return True if text is None, empty, or contains only whitespace."""
    return not text or not text.strip()


def is_hex(text: str) -> bool:
    """
    Return True if text contains only valid hexadecimal characters.
    Does not require a specific length.
    """
    if is_empty(text):
        return False
    return bool(re.fullmatch(r"[0-9a-fA-F]+", text.strip()))


def is_base64(text: str) -> bool:
    """
    Return True if text is a structurally valid Base64-encoded string.
    Checks character set, padding alignment, and attempts a decode.
    """
    if is_empty(text):
        return False

    stripped = text.strip()

    # Pad to a multiple of 4 before validating
    remainder = len(stripped) % 4
    if remainder == 2:
        padded = stripped + "=="
    elif remainder == 3:
        padded = stripped + "="
    else:
        padded = stripped

    if not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", padded):
        return False

    try:
        base64.b64decode(padded, validate=True)
        return True
    except (binascii.Error, ValueError):
        return False


def is_url_encoded(text: str) -> bool:
    """
    Return True if text contains at least one valid percent-encoded sequence
    (%XX where XX are two hexadecimal digits).
    """
    if is_empty(text):
        return False
    return bool(re.search(r"%[0-9a-fA-F]{2}", text))


def validate_input(text: str) -> tuple[bool, str]:
    """
    Validate a raw user input string for general use across CipherScope.

    Checks:
    - Not empty or whitespace-only
    - Contains at least one printable character
    - Does not exceed the maximum allowed length (10,000 characters)

    Args:
        text: The raw input string to validate.

    Returns:
        A (valid: bool, message: str) tuple.
        message is empty on success, or describes the failure reason.
    """
    if is_empty(text):
        return False, "Input is empty."

    if len(text) > 10_000:
        return False, f"Input is too long ({len(text)} chars). Maximum is 10,000."

    if not any(ch.isprintable() for ch in text):
        return False, "Input contains no printable characters."

    return True, ""
