"""
CipherScope v1.0
CLI Cipher & Hash Analyzer.
"""

# --- Detection & decoding imports ---
from detector import detect_type

from decoders.base64_decoder import decode_base64
from decoders.hex_decoder import decode_hex
from decoders.url_decoder import decode_url
from decoders.rot13_decoder import decode_rot13
from decoders.caesar_decoder import decode_caesar
from decoders.atbash_decoder import decode_atbash

from detectors.cipher_detector import detect_cipher
from detectors.hash_detector import detect_hash

# --- Shared utilities ---
from utils.validators import validate_input
from utils.formatters import (
    format_detection,
    format_decode_result,
    format_hash_candidates,
    format_cipher_candidates,
)

APP_NAME = "CipherScope"
VERSION = "1.0"


# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------

def display_banner() -> None:
    print(f"\n{'=' * 40}")
    print(f"  {APP_NAME} v{VERSION}")
    print(f"  Cipher & Hash Analyzer")
    print(f"{'=' * 40}\n")


def get_input() -> str | None:
    """Prompt for user input. Returns None on exit/interrupt."""
    while True:
        try:
            user_input = input("Enter string (or 'exit' to quit): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nInterrupted. Exiting.")
            return None

        if user_input.lower() == "exit":
            return None

        if not user_input:
            print("  [!] Input cannot be empty. Please try again.\n")
            continue

        return user_input


# ---------------------------------------------------------------------------
# Analysis pipeline
# ---------------------------------------------------------------------------

def analyze(text: str) -> None:
    """
    Full analysis pipeline: validate → detect → decode/analyze → display.
    """
    # 1. Validate
    ok, error_msg = validate_input(text)
    if not ok:
        print(f"\n  [!] {error_msg}\n")
        return

    print(f"\n  Input  : {text}")

    # 2. Detect type
    detection = detect_type(text)
    print(format_detection(detection))

    det_type = detection.type

    # 3a. Direct decoder for encoding types
    if det_type == "URL Encoding":
        print(format_decode_result(decode_url(text)))

    elif det_type == "Base64":
        print(format_decode_result(decode_base64(text)))

    elif det_type == "Hexadecimal":
        print(format_decode_result(decode_hex(text)))

    elif det_type == "ROT13":
        print(format_decode_result(decode_rot13(text)))

    # 3b. Hash type — show candidates (no cracking)
    elif det_type.startswith("Hash"):
        hash_candidates = detect_hash(text)
        print(format_hash_candidates(hash_candidates))

    # 3c. Unknown — try classical cipher heuristics and hash detection
    elif det_type == "Unknown":
        _try_unknown(text)

    # 3d. Any other classified type — pass through gracefully
    else:
        print(f"  No decoder available for type: {det_type}\n")


def _try_unknown(text: str) -> None:
    """
    For Unknown-type inputs: run cipher and hash heuristic detection
    and display the best candidates found.
    """
    cipher_candidates = detect_cipher(text)
    hash_candidates = detect_hash(text)

    if not cipher_candidates and not hash_candidates:
        print("  No known encoding, cipher, or hash pattern identified.\n")
        return

    # Show cipher candidates with decoded previews
    if cipher_candidates:
        print(format_cipher_candidates(cipher_candidates))

        # Auto-decode using the top-ranked cipher if confidence is High/Medium
        top = cipher_candidates[0]
        if top.confidence in ("High", "Medium"):
            _auto_decode_cipher(text, top.cipher)

    # Show hash candidates (structure-based, no cracking)
    if hash_candidates:
        print(format_hash_candidates(hash_candidates))


def _auto_decode_cipher(text: str, cipher: str) -> None:
    """
    Automatically decode using the best cipher candidate and display result.
    Handles ROT13, Atbash, and Caesar (all 25 shifts tried as one result).
    """
    if cipher == "ROT13":
        print(format_decode_result(decode_rot13(text)))

    elif cipher == "Atbash":
        print(format_decode_result(decode_atbash(text)))

    elif cipher.startswith("Caesar"):
        # Extract shift from label "Caesar (shift=N)"
        try:
            shift = int(cipher.split("=")[1].rstrip(")"))
            print(format_decode_result(decode_caesar(text, shift)))
        except (IndexError, ValueError):
            pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    display_banner()

    while True:
        user_input = get_input()

        if user_input is None:
            print("Goodbye!")
            break

        try:
            analyze(user_input)
        except Exception as exc:  # noqa: BLE001
            print(f"\n  [!] Unexpected error: {exc}\n")

        print()


if __name__ == "__main__":
    main()
