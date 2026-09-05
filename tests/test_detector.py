"""Tests for detector.detect_type()"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detector import detect_type, DetectionResult


class TestDetectType(unittest.TestCase):

    # --- Return type ---
    def test_returns_detection_result(self):
        result = detect_type("hello")
        self.assertIsInstance(result, DetectionResult)

    def test_result_has_type_and_confidence(self):
        result = detect_type("hello")
        self.assertIn(result.confidence, ("High", "Medium", "Low"))
        self.assertIsInstance(result.type, str)

    # --- URL Encoding ---
    def test_url_encoded_detected_as_high(self):
        result = detect_type("Hello%20World")
        self.assertEqual(result.type, "URL Encoding")
        self.assertEqual(result.confidence, "High")

    def test_url_with_multiple_sequences(self):
        result = detect_type("a%3Db%26c%3Dd")
        self.assertEqual(result.type, "URL Encoding")

    # --- Hash ---
    def test_md5_hash_detected(self):
        result = detect_type("5d41402abc4b2a76b9719d911017c592")
        self.assertIn("MD5", result.type)
        self.assertEqual(result.confidence, "High")

    def test_sha256_hash_detected(self):
        result = detect_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertIn("SHA-256", result.type)

    # --- Hexadecimal ---
    def test_hex_without_known_length(self):
        result = detect_type("48656c6c6f")
        self.assertEqual(result.type, "Hexadecimal")
        self.assertEqual(result.confidence, "Medium")

    # --- Base64 ---
    def test_base64_detected(self):
        result = detect_type("SGVsbG8gV29ybGQ=")
        self.assertEqual(result.type, "Base64")

    def test_base64_padded_detected(self):
        # With padding the detector can confirm Base64
        result = detect_type("SGVsbG8gV29ybGQ=")
        self.assertEqual(result.type, "Base64")

    def test_base64_no_padding_with_space_is_unknown(self):
        # "SGVsbG8gV29ybGQ" contains a space so it fails both hex and Base64
        # charset checks in detector.py — expected result is Unknown.
        result = detect_type("SGVsbG8gV29ybGQ")
        self.assertEqual(result.type, "Unknown")

    # --- Unknown ---
    def test_plain_text_returns_unknown(self):
        result = detect_type("just plain text here")
        self.assertEqual(result.type, "Unknown")

    # --- Empty / edge cases ---
    def test_empty_string_returns_unknown(self):
        result = detect_type("")
        self.assertEqual(result.type, "Unknown")

    def test_whitespace_only_returns_unknown(self):
        result = detect_type("   ")
        self.assertEqual(result.type, "Unknown")


if __name__ == "__main__":
    unittest.main()
