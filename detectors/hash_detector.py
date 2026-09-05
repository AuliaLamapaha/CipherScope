"""
CipherScope - detectors/hash_detector.py
Detects probable hash algorithm(s) from a string based on structural characteristics.
"""

import re
from typing import NamedTuple


class HashCandidate(NamedTuple):
    algorithm: str  # e.g. "MD5", "SHA-256", "bcrypt"
    confidence: str # "High", "Medium", or "Low"
    note: str       # short human-readable rationale


# Hex-based hash algorithms: length -> list of possible names
_HEX_LENGTHS: dict[int, list[str]] = {
    32:  ["MD5", "NTLM", "MD4"],
    40:  ["SHA-1", "RIPEMD-160"],
    56:  ["SHA-224", "SHA3-224"],
    64:  ["SHA-256", "SHA3-256", "BLAKE2s"],
    96:  ["SHA-384", "SHA3-384"],
    128: ["SHA-512", "SHA3-512", "BLAKE2b"],
}

# Modern KDF / password hash prefixes
_PREFIX_PATTERNS: list[tuple[str, str, str]] = [
    # (regex pattern, algorithm name, note)
    (r"^\$2[aby]\$\d{2}\$.{53}$",  "bcrypt",  "prefix $2a$/$2b$/$2y$, 60-char total"),
    (r"^\$argon2(i|d|id)\$",        "Argon2",  "prefix $argon2i/argon2d/argon2id"),
    (r"^\$scrypt\$",                "scrypt",  "prefix $scrypt$"),
    (r"^\$pbkdf2",                  "PBKDF2",  "prefix $pbkdf2"),
    (r"^\$5\$",                     "SHA-256 crypt (Unix)", "prefix $5$"),
    (r"^\$6\$",                     "SHA-512 crypt (Unix)", "prefix $6$"),
    (r"^\$1\$",                     "MD5 crypt (Unix)",     "prefix $1$"),
]


def _is_hex(text: str) -> bool:
    """Return True if text contains only hexadecimal characters."""
    return bool(re.fullmatch(r"[0-9a-fA-F]+", text))


def detect_hash(text: str) -> list[HashCandidate]:
    """
    Detect probable hash algorithm(s) from the input string.

    Uses two strategies:
    1. Prefix matching for modern KDF formats (bcrypt, Argon2, scrypt, …).
    2. Length + character-set matching for raw hex digests.

    Multiple candidates are returned when a length is shared by more than
    one algorithm. Results are not a guarantee — they are heuristic inferences.
    No hashing, cracking, or brute-force is performed.

    Args:
        text: The string to analyse.

    Returns:
        A list of HashCandidate items, or an empty list if nothing matches.
    """
    if not text or not text.strip():
        return []

    stripped = text.strip()
    candidates: list[HashCandidate] = []

    # --- Strategy 1: prefix-based KDF detection ---
    for pattern, algorithm, note in _PREFIX_PATTERNS:
        if re.match(pattern, stripped):
            candidates.append(HashCandidate(algorithm, "High", note))

    if candidates:
        return candidates

    # --- Strategy 2: hex digest detection ---
    if not _is_hex(stripped):
        return []

    length = len(stripped)
    algorithms = _HEX_LENGTHS.get(length)

    if not algorithms:
        return []

    # Single match at this length -> High confidence; multiple -> Medium
    confidence = "High" if len(algorithms) == 1 else "Medium"
    note_base = f"{length}-char hex digest"

    for algo in algorithms:
        candidates.append(HashCandidate(algo, confidence, note_base))

    return candidates
