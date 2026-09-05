"""
CipherScope - utils/formatters.py
Shared formatting helpers that convert CipherScope result objects
into consistent, human-readable CLI strings.

This module only formats — it never calls decoders or detectors.
"""

_LINE = "-" * 42
_CONF_BADGE = {"High": "[!!!]", "Medium": "[!! ]", "Low": "[ ! ]"}


def _badge(confidence: str) -> str:
    """Return a short visual badge for a confidence level."""
    return _CONF_BADGE.get(confidence, "[ ? ]")


def format_detection(result) -> str:
    """
    Format a single DetectionResult (from detector.detect_type).

    Args:
        result: An object with .type (str) and .confidence (str).

    Returns:
        A single-line string suitable for CLI output.
    """
    badge = _badge(result.confidence)
    return f"  {badge} Detected type : {result.type}  [{result.confidence} confidence]"


def format_decode_result(result) -> str:
    """
    Format a single DecodeResult (from any decoders.* module).

    Args:
        result: An object with .success (bool), .output (str),
                and .encoding (str).

    Returns:
        A multi-line string block suitable for CLI output.
    """
    lines = [_LINE]
    if result.success:
        lines.append(f"  Status   : OK")
        lines.append(f"  Encoding : {result.encoding}")
        # Truncate very long decoded output to keep the terminal readable
        output = result.output
        if len(output) > 200:
            output = output[:200] + f"  ... ({len(result.output)} chars total)"
        lines.append(f"  Decoded  : {output}")
    else:
        lines.append(f"  Status   : FAILED")
        lines.append(f"  Reason   : {result.output}")
    lines.append(_LINE)
    return "\n".join(lines)


def format_hash_candidates(candidates) -> str:
    """
    Format a list of HashCandidate objects (from detectors.hash_detector).

    Args:
        candidates: A list of objects with .algorithm, .confidence, .note.

    Returns:
        A multi-line string block, or a 'no match' notice if the list
        is empty.
    """
    lines = [_LINE]
    if not candidates:
        lines.append("  No hash algorithm candidates identified.")
    else:
        lines.append(f"  Hash candidates ({len(candidates)} found):")
        for c in candidates:
            badge = _badge(c.confidence)
            lines.append(f"    {badge} {c.algorithm:<22}  [{c.confidence}]  {c.note}")
    lines.append(_LINE)
    return "\n".join(lines)


def format_cipher_candidates(candidates) -> str:
    """
    Format a list of CipherCandidate objects (from detectors.cipher_detector).

    Args:
        candidates: A list of objects with .cipher, .decoded, .confidence.

    Returns:
        A multi-line string block showing each candidate and its decoded
        preview, or a 'no match' notice if the list is empty.
    """
    lines = [_LINE]
    if not candidates:
        lines.append("  No classical cipher candidates identified.")
    else:
        lines.append(f"  Cipher candidates ({len(candidates)} found):")
        for c in candidates:
            badge = _badge(c.confidence)
            preview = c.decoded[:60] + "..." if len(c.decoded) > 60 else c.decoded
            lines.append(f"    {badge} {c.cipher:<22}  [{c.confidence}]")
            lines.append(f"         Decoded preview : {preview}")
    lines.append(_LINE)
    return "\n".join(lines)
