"""Tests for detectors.cipher_detector.detect_cipher()"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detectors.cipher_detector import detect_cipher, CipherCandidate


class TestDetectCipher(unittest.TestCase):

    # --- Return type ---
    def test_returns_list(self):
        result = detect_cipher("Uryyb Jbeyq")
        self.assertIsInstance(result, list)

    def test_candidates_are_cipher_candidate(self):
        result = detect_cipher("Uryyb Jbeyq")
        for c in result:
            self.assertIsInstance(c, CipherCandidate)

    def test_confidence_values_valid(self):
        result = detect_cipher("Uryyb Jbeyq")
        for c in result:
            self.assertIn(c.confidence, ("High", "Medium", "Low"))

    # --- ROT13 detection ---
    def test_rot13_detected(self):
        result = detect_cipher("Uryyb Jbeyq")
        ciphers = [c.cipher for c in result]
        self.assertIn("ROT13", ciphers)

    def test_rot13_decoded_correctly(self):
        result = detect_cipher("Uryyb Jbeyq")
        rot = next(c for c in result if c.cipher == "ROT13")
        self.assertEqual(rot.decoded, "Hello World")

    def test_rot13_high_confidence(self):
        result = detect_cipher("Uryyb Jbeyq")
        rot = next(c for c in result if c.cipher == "ROT13")
        self.assertEqual(rot.confidence, "High")

    # --- Caesar detection ---
    def test_caesar_shift3_detected(self):
        result = detect_cipher("Khoor Zruog")
        ciphers = [c.cipher for c in result]
        self.assertIn("Caesar (shift=3)", ciphers)

    def test_caesar_decoded_correctly(self):
        result = detect_cipher("Khoor Zruog")
        caesar = next(c for c in result if c.cipher == "Caesar (shift=3)")
        self.assertEqual(caesar.decoded, "Hello World")

    # --- Atbash detection ---
    def test_atbash_detected(self):
        result = detect_cipher("Svool Dliow")
        ciphers = [c.cipher for c in result]
        self.assertIn("Atbash", ciphers)

    def test_atbash_decoded_correctly(self):
        result = detect_cipher("Svool Dliow")
        atbash = next(c for c in result if c.cipher == "Atbash")
        self.assertEqual(atbash.decoded, "Hello World")

    # --- Sorted by confidence (best first) ---
    def test_results_sorted_best_first(self):
        result = detect_cipher("Uryyb Jbeyq")
        if len(result) > 1:
            order = {"High": 0, "Medium": 1, "Low": 2}
            scores = [order[c.confidence] for c in result]
            self.assertEqual(scores, sorted(scores))

    # --- Empty / edge cases ---
    def test_empty_returns_empty_list(self):
        self.assertEqual(detect_cipher(""), [])

    def test_whitespace_returns_empty_list(self):
        self.assertEqual(detect_cipher("   "), [])

    def test_digits_only_returns_empty_list(self):
        self.assertEqual(detect_cipher("12345"), [])

    def test_gibberish_returns_empty_list(self):
        self.assertEqual(detect_cipher("xyzxyzxyzxyz"), [])

    def test_plain_english_no_candidates(self):
        # Plain English should NOT match any cipher
        self.assertEqual(detect_cipher("Hello World"), [])


if __name__ == "__main__":
    unittest.main()
