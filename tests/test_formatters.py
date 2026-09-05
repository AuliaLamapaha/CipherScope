"""Tests for utils.formatters"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.formatters import (
    format_detection,
    format_decode_result,
    format_hash_candidates,
    format_cipher_candidates,
)
from detector import DetectionResult
from decoders.base64_decoder import DecodeResult as B64R
from detectors.hash_detector import HashCandidate
from detectors.cipher_detector import CipherCandidate


class TestFormatDetection(unittest.TestCase):

    def test_returns_string(self):
        result = format_detection(DetectionResult("Base64", "Medium"))
        self.assertIsInstance(result, str)

    def test_contains_type(self):
        result = format_detection(DetectionResult("Base64", "Medium"))
        self.assertIn("Base64", result)

    def test_contains_confidence(self):
        result = format_detection(DetectionResult("URL Encoding", "High"))
        self.assertIn("High", result)

    def test_high_badge(self):
        result = format_detection(DetectionResult("URL Encoding", "High"))
        self.assertIn("[!!!]", result)

    def test_medium_badge(self):
        result = format_detection(DetectionResult("Base64", "Medium"))
        self.assertIn("[!! ]", result)

    def test_low_badge(self):
        result = format_detection(DetectionResult("Unknown", "Low"))
        self.assertIn("[ ! ]", result)


class TestFormatDecodeResult(unittest.TestCase):

    def test_success_contains_ok(self):
        r = B64R(True, "Hello World", "utf-8")
        out = format_decode_result(r)
        self.assertIn("OK", out)

    def test_success_contains_output(self):
        r = B64R(True, "Hello World", "utf-8")
        out = format_decode_result(r)
        self.assertIn("Hello World", out)

    def test_success_contains_encoding(self):
        r = B64R(True, "Hello World", "utf-8")
        out = format_decode_result(r)
        self.assertIn("utf-8", out)

    def test_failure_contains_failed(self):
        r = B64R(False, "Input is empty.", "")
        out = format_decode_result(r)
        self.assertIn("FAILED", out)

    def test_failure_contains_reason(self):
        r = B64R(False, "Input is empty.", "")
        out = format_decode_result(r)
        self.assertIn("Input is empty.", out)

    def test_long_output_truncated(self):
        long_text = "A" * 300
        r = B64R(True, long_text, "utf-8")
        out = format_decode_result(r)
        self.assertIn("300 chars total", out)
        # The raw 300-char string should NOT appear verbatim
        self.assertNotIn("A" * 201, out)

    def test_returns_string(self):
        r = B64R(True, "test", "utf-8")
        self.assertIsInstance(format_decode_result(r), str)


class TestFormatHashCandidates(unittest.TestCase):

    def test_empty_list_no_candidates_message(self):
        out = format_hash_candidates([])
        self.assertIn("No hash algorithm", out)

    def test_contains_algorithm_name(self):
        candidates = [HashCandidate("MD5", "Medium", "32-char hex digest")]
        out = format_hash_candidates(candidates)
        self.assertIn("MD5", out)

    def test_contains_confidence(self):
        candidates = [HashCandidate("MD5", "Medium", "32-char hex digest")]
        out = format_hash_candidates(candidates)
        self.assertIn("Medium", out)

    def test_contains_note(self):
        candidates = [HashCandidate("MD5", "Medium", "32-char hex digest")]
        out = format_hash_candidates(candidates)
        self.assertIn("32-char hex digest", out)

    def test_multiple_candidates(self):
        candidates = [
            HashCandidate("MD5",  "Medium", "32-char hex digest"),
            HashCandidate("NTLM", "Medium", "32-char hex digest"),
        ]
        out = format_hash_candidates(candidates)
        self.assertIn("MD5", out)
        self.assertIn("NTLM", out)
        self.assertIn("2 found", out)

    def test_returns_string(self):
        self.assertIsInstance(format_hash_candidates([]), str)

    def test_high_badge_for_bcrypt(self):
        candidates = [HashCandidate("bcrypt", "High", "prefix $2b$")]
        out = format_hash_candidates(candidates)
        self.assertIn("[!!!]", out)


class TestFormatCipherCandidates(unittest.TestCase):

    def test_empty_list_no_candidates_message(self):
        out = format_cipher_candidates([])
        self.assertIn("No classical cipher", out)

    def test_contains_cipher_name(self):
        candidates = [CipherCandidate("ROT13", "Hello World", "High")]
        out = format_cipher_candidates(candidates)
        self.assertIn("ROT13", out)

    def test_contains_decoded_preview(self):
        candidates = [CipherCandidate("ROT13", "Hello World", "High")]
        out = format_cipher_candidates(candidates)
        self.assertIn("Hello World", out)

    def test_contains_confidence(self):
        candidates = [CipherCandidate("ROT13", "Hello World", "High")]
        out = format_cipher_candidates(candidates)
        self.assertIn("High", out)

    def test_long_decoded_truncated(self):
        long_decoded = "A" * 80
        candidates = [CipherCandidate("ROT13", long_decoded, "Low")]
        out = format_cipher_candidates(candidates)
        self.assertIn("...", out)

    def test_multiple_candidates(self):
        candidates = [
            CipherCandidate("ROT13",          "Hello World", "High"),
            CipherCandidate("Caesar (shift=3)", "Hello World", "High"),
        ]
        out = format_cipher_candidates(candidates)
        self.assertIn("ROT13", out)
        self.assertIn("Caesar", out)
        self.assertIn("2 found", out)

    def test_returns_string(self):
        self.assertIsInstance(format_cipher_candidates([]), str)


if __name__ == "__main__":
    unittest.main()
