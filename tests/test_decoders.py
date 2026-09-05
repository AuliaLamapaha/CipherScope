"""Tests for all decoders: base64, hex, url, rot13, caesar, atbash."""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from decoders.base64_decoder import decode_base64
from decoders.hex_decoder import decode_hex
from decoders.url_decoder import decode_url
from decoders.rot13_decoder import decode_rot13
from decoders.caesar_decoder import decode_caesar
from decoders.atbash_decoder import decode_atbash


class TestBase64Decoder(unittest.TestCase):

    def test_valid_padded(self):
        r = decode_base64("SGVsbG8gV29ybGQ=")
        self.assertTrue(r.success)
        self.assertEqual(r.output, "Hello World")
        self.assertEqual(r.encoding, "utf-8")

    def test_valid_no_padding(self):
        r = decode_base64("SGVsbG8gV29ybGQ")
        self.assertTrue(r.success)
        self.assertEqual(r.output, "Hello World")

    def test_empty_input(self):
        r = decode_base64("")
        self.assertFalse(r.success)
        self.assertEqual(r.encoding, "")

    def test_whitespace_only(self):
        r = decode_base64("   ")
        self.assertFalse(r.success)

    def test_invalid_characters(self):
        r = decode_base64("Not!Base64!!")
        self.assertFalse(r.success)

    def test_latin1_fallback(self):
        # /9j/ is the start of a JPEG base64 — non-UTF-8 bytes
        r = decode_base64("/9j/4AAQSkZJRgAB")
        self.assertTrue(r.success)
        self.assertEqual(r.encoding, "latin-1")


class TestHexDecoder(unittest.TestCase):

    def test_valid_hex(self):
        r = decode_hex("48656c6c6f20576f726c64")
        self.assertTrue(r.success)
        self.assertEqual(r.output, "Hello World")
        self.assertEqual(r.encoding, "utf-8")

    def test_uppercase_hex(self):
        r = decode_hex("48656C6C6F")
        self.assertTrue(r.success)
        self.assertEqual(r.output, "Hello")

    def test_empty_input(self):
        r = decode_hex("")
        self.assertFalse(r.success)

    def test_whitespace_only(self):
        r = decode_hex("   ")
        self.assertFalse(r.success)

    def test_invalid_character(self):
        r = decode_hex("4G656c6c6f")
        self.assertFalse(r.success)

    def test_odd_length(self):
        r = decode_hex("48656c6c6")
        self.assertFalse(r.success)
        self.assertIn("Odd", r.output)

    def test_latin1_fallback(self):
        r = decode_hex("ffd8ffe000104a464946")
        self.assertTrue(r.success)
        self.assertEqual(r.encoding, "latin-1")


class TestUrlDecoder(unittest.TestCase):

    def test_standard_spaces(self):
        r = decode_url("Hello%20World%21")
        self.assertTrue(r.success)
        self.assertEqual(r.output, "Hello World!")

    def test_email_address(self):
        r = decode_url("user%40example.com")
        self.assertTrue(r.success)
        self.assertEqual(r.output, "user@example.com")

    def test_slashes(self):
        r = decode_url("path%2Fto%2Fresource")
        self.assertTrue(r.success)
        self.assertEqual(r.output, "path/to/resource")

    def test_empty_input(self):
        r = decode_url("")
        self.assertFalse(r.success)

    def test_whitespace_only(self):
        r = decode_url("   ")
        self.assertFalse(r.success)

    def test_no_encoding(self):
        r = decode_url("no-encoding-here")
        self.assertFalse(r.success)
        self.assertIn("No percent-encoded", r.output)

    def test_invalid_percent_sequence(self):
        r = decode_url("%GG%ZZ")
        self.assertFalse(r.success)

    def test_utf8_multibyte(self):
        r = decode_url("%C3%A9l%C3%A8ve")
        self.assertTrue(r.success)
        self.assertEqual(r.encoding, "utf-8")


class TestRot13Decoder(unittest.TestCase):

    def test_hello_world(self):
        r = decode_rot13("Uryyb Jbeyq")
        self.assertTrue(r.success)
        self.assertEqual(r.output, "Hello World")
        self.assertEqual(r.encoding, "rot13")

    def test_reversible(self):
        original = "Hello, CipherScope!"
        r1 = decode_rot13(original)
        r2 = decode_rot13(r1.output)
        self.assertEqual(r2.output, original)

    def test_non_alpha_unchanged(self):
        r = decode_rot13("ABC 123!@#")
        self.assertTrue(r.success)
        self.assertEqual(r.output, "NOP 123!@#")

    def test_empty_input(self):
        r = decode_rot13("")
        self.assertFalse(r.success)

    def test_whitespace_only(self):
        r = decode_rot13("   ")
        self.assertFalse(r.success)

    def test_upper_and_lower(self):
        # N->A, b->o, P->C, q->d
        r = decode_rot13("NbPq")
        self.assertTrue(r.success)
        self.assertEqual(r.output, "AoCd")


class TestCaesarDecoder(unittest.TestCase):

    def test_shift_3(self):
        r = decode_caesar("Khoor Zruog", 3)
        self.assertTrue(r.success)
        self.assertEqual(r.output, "Hello World")

    def test_shift_0_no_change(self):
        r = decode_caesar("Hello", 0)
        self.assertTrue(r.success)
        self.assertEqual(r.output, "Hello")

    def test_wrap_around(self):
        r = decode_caesar("ABC", 1)
        self.assertTrue(r.success)
        self.assertEqual(r.output, "ZAB")

    def test_non_alpha_unchanged(self):
        r = decode_caesar("Khoor 123!", 3)
        self.assertTrue(r.success)
        self.assertIn("123!", r.output)

    def test_encoding_label(self):
        r = decode_caesar("Khoor", 3)
        self.assertEqual(r.encoding, "caesar-shift-3")

    def test_reversible(self):
        original = "The Quick Brown Fox"
        encoded = decode_caesar(original, 25).output
        restored = decode_caesar(encoded, 1).output
        self.assertEqual(restored, original)

    def test_empty_input(self):
        r = decode_caesar("", 3)
        self.assertFalse(r.success)

    def test_whitespace_only(self):
        r = decode_caesar("   ", 3)
        self.assertFalse(r.success)

    def test_shift_out_of_range_high(self):
        r = decode_caesar("hello", 26)
        self.assertFalse(r.success)
        self.assertIn("out of range", r.output)

    def test_shift_negative(self):
        r = decode_caesar("hello", -1)
        self.assertFalse(r.success)

    def test_shift_float(self):
        r = decode_caesar("hello", 1.5)   # type: ignore
        self.assertFalse(r.success)

    def test_shift_bool_rejected(self):
        r = decode_caesar("hello", True)  # type: ignore
        self.assertFalse(r.success)


class TestAtbashDecoder(unittest.TestCase):

    def test_hello_world(self):
        r = decode_atbash("Svool Dliow")
        self.assertTrue(r.success)
        self.assertEqual(r.output, "Hello World")
        self.assertEqual(r.encoding, "atbash")

    def test_reversible(self):
        original = "Hello, CipherScope!"
        r1 = decode_atbash(original)
        r2 = decode_atbash(r1.output)
        self.assertEqual(r2.output, original)

    def test_full_alphabet_upper(self):
        r = decode_atbash("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        self.assertTrue(r.success)
        self.assertEqual(r.output, "ZYXWVUTSRQPONMLKJIHGFEDCBA")

    def test_full_alphabet_lower(self):
        r = decode_atbash("abcdefghijklmnopqrstuvwxyz")
        self.assertTrue(r.success)
        self.assertEqual(r.output, "zyxwvutsrqponmlkjihgfedcba")

    def test_non_alpha_unchanged(self):
        r = decode_atbash("Hello 123!")
        self.assertTrue(r.success)
        self.assertIn("123!", r.output)

    def test_empty_input(self):
        r = decode_atbash("")
        self.assertFalse(r.success)

    def test_whitespace_only(self):
        r = decode_atbash("   ")
        self.assertFalse(r.success)


if __name__ == "__main__":
    unittest.main()
