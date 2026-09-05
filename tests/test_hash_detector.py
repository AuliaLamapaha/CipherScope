"""Tests for detectors.hash_detector.detect_hash()"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detectors.hash_detector import detect_hash, HashCandidate

# Real-world hex digests (correct lengths)
MD5    = "5d41402abc4b2a76b9719d911017c592"          # 32
SHA1   = "aaf4c61ddcc5e8a2dabede0f3b482cd9ead53c53"  # 40
SHA224 = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"  # 56
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # 64
SHA384 = "a" * 96   # 96 hex chars
SHA512 = "b" * 128  # 128 hex chars
BCRYPT = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"
ARGON2 = "$argon2id$v=19$m=65536,t=2,p=1$abc123"
SCRYPT = "$scrypt$ln=16,r=8,p=1$abc$xyz"
UNIX6  = "$6$rounds=5000$salt$hash"
UNIX5  = "$5$rounds=5000$salt$hash"
UNIX1  = "$1$salt$hash"


class TestDetectHash(unittest.TestCase):

    # --- Return type ---
    def test_returns_list(self):
        self.assertIsInstance(detect_hash(MD5), list)

    def test_candidates_are_hash_candidate(self):
        for c in detect_hash(MD5):
            self.assertIsInstance(c, HashCandidate)

    def test_confidence_values_valid(self):
        for c in detect_hash(MD5):
            self.assertIn(c.confidence, ("High", "Medium", "Low"))

    # --- Hex digest lengths ---
    def test_md5_candidates(self):
        algos = [c.algorithm for c in detect_hash(MD5)]
        self.assertIn("MD5", algos)

    def test_sha1_candidates(self):
        algos = [c.algorithm for c in detect_hash(SHA1)]
        self.assertIn("SHA-1", algos)

    def test_sha224_candidates(self):
        algos = [c.algorithm for c in detect_hash(SHA224)]
        self.assertIn("SHA-224", algos)

    def test_sha256_candidates(self):
        algos = [c.algorithm for c in detect_hash(SHA256)]
        self.assertIn("SHA-256", algos)

    def test_sha384_candidates(self):
        algos = [c.algorithm for c in detect_hash(SHA384)]
        self.assertIn("SHA-384", algos)

    def test_sha512_candidates(self):
        algos = [c.algorithm for c in detect_hash(SHA512)]
        self.assertIn("SHA-512", algos)

    # --- Hex confidence is Medium (shared lengths) ---
    def test_hex_digest_confidence_is_medium(self):
        for c in detect_hash(MD5):
            self.assertEqual(c.confidence, "Medium")

    # --- KDF / modern formats ---
    def test_bcrypt_detected(self):
        result = detect_hash(BCRYPT)
        algos = [c.algorithm for c in result]
        self.assertIn("bcrypt", algos)

    def test_bcrypt_confidence_is_high(self):
        result = detect_hash(BCRYPT)
        bcrypt = next(c for c in result if c.algorithm == "bcrypt")
        self.assertEqual(bcrypt.confidence, "High")

    def test_argon2_detected(self):
        algos = [c.algorithm for c in detect_hash(ARGON2)]
        self.assertIn("Argon2", algos)

    def test_scrypt_detected(self):
        algos = [c.algorithm for c in detect_hash(SCRYPT)]
        self.assertIn("scrypt", algos)

    def test_unix_sha512_crypt_detected(self):
        algos = [c.algorithm for c in detect_hash(UNIX6)]
        self.assertIn("SHA-512 crypt (Unix)", algos)

    def test_unix_sha256_crypt_detected(self):
        algos = [c.algorithm for c in detect_hash(UNIX5)]
        self.assertIn("SHA-256 crypt (Unix)", algos)

    def test_unix_md5_crypt_detected(self):
        algos = [c.algorithm for c in detect_hash(UNIX1)]
        self.assertIn("MD5 crypt (Unix)", algos)

    # --- No match cases ---
    def test_empty_returns_empty_list(self):
        self.assertEqual(detect_hash(""), [])

    def test_whitespace_returns_empty_list(self):
        self.assertEqual(detect_hash("   "), [])

    def test_invalid_chars_returns_empty(self):
        self.assertEqual(detect_hash("notahex!!"), [])

    def test_hex_unknown_length_returns_empty(self):
        # 10 hex chars — not in any known hash length
        self.assertEqual(detect_hash("abcdef1234"), [])

    def test_plain_text_returns_empty(self):
        self.assertEqual(detect_hash("Hello World"), [])


if __name__ == "__main__":
    unittest.main()
