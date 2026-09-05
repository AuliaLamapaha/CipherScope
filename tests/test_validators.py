"""Tests for utils.validators"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.validators import is_empty, is_hex, is_base64, is_url_encoded, validate_input


class TestIsEmpty(unittest.TestCase):

    def test_empty_string(self):
        self.assertTrue(is_empty(""))

    def test_whitespace_only(self):
        self.assertTrue(is_empty("   "))

    def test_none(self):
        self.assertTrue(is_empty(None))   # type: ignore

    def test_non_empty(self):
        self.assertFalse(is_empty("hello"))

    def test_single_char(self):
        self.assertFalse(is_empty("x"))

    def test_spaces_around_text(self):
        self.assertFalse(is_empty("  x  "))


class TestIsHex(unittest.TestCase):

    def test_lowercase_hex(self):
        self.assertTrue(is_hex("48656c6c6f"))

    def test_uppercase_hex(self):
        self.assertTrue(is_hex("DEADBEEF"))

    def test_mixed_case_hex(self):
        self.assertTrue(is_hex("DeAdBeEf"))

    def test_single_char(self):
        self.assertTrue(is_hex("0"))

    def test_invalid_char_g(self):
        self.assertFalse(is_hex("4G656c"))

    def test_invalid_special(self):
        self.assertFalse(is_hex("48!65"))

    def test_empty(self):
        self.assertFalse(is_hex(""))

    def test_whitespace(self):
        self.assertFalse(is_hex("   "))

    def test_spaces_in_middle(self):
        self.assertFalse(is_hex("48 65"))


class TestIsBase64(unittest.TestCase):

    def test_padded_valid(self):
        self.assertTrue(is_base64("SGVsbG8="))

    def test_double_padded(self):
        self.assertTrue(is_base64("SGVsbG8gV29ybGQ="))

    def test_no_padding(self):
        self.assertTrue(is_base64("SGVsbG8gV29ybGQ"))

    def test_short_valid(self):
        self.assertTrue(is_base64("YQ=="))

    def test_invalid_char(self):
        self.assertFalse(is_base64("SGVs!G8="))

    def test_empty(self):
        self.assertFalse(is_base64(""))

    def test_whitespace(self):
        self.assertFalse(is_base64("   "))

    def test_plain_text(self):
        self.assertFalse(is_base64("Hello World!!"))


class TestIsUrlEncoded(unittest.TestCase):

    def test_space_encoded(self):
        self.assertTrue(is_url_encoded("Hello%20World"))

    def test_multiple_sequences(self):
        self.assertTrue(is_url_encoded("a%3Db%26c%3Dd"))

    def test_single_sequence(self):
        self.assertTrue(is_url_encoded("x%2Fy"))

    def test_no_encoding(self):
        self.assertFalse(is_url_encoded("no-encoding"))

    def test_invalid_percent_sequence(self):
        self.assertFalse(is_url_encoded("%GG"))

    def test_empty(self):
        self.assertFalse(is_url_encoded(""))

    def test_whitespace(self):
        self.assertFalse(is_url_encoded("   "))


class TestValidateInput(unittest.TestCase):

    def test_valid_string(self):
        ok, msg = validate_input("hello")
        self.assertTrue(ok)
        self.assertEqual(msg, "")

    def test_empty_string(self):
        ok, msg = validate_input("")
        self.assertFalse(ok)
        self.assertIn("empty", msg.lower())

    def test_whitespace_only(self):
        ok, msg = validate_input("   ")
        self.assertFalse(ok)

    def test_too_long(self):
        ok, msg = validate_input("a" * 10001)
        self.assertFalse(ok)
        self.assertIn("long", msg.lower())

    def test_exactly_max_length(self):
        ok, _ = validate_input("a" * 10000)
        self.assertTrue(ok)

    def test_non_printable_only(self):
        ok, msg = validate_input("\x00\x01\x02")
        self.assertFalse(ok)
        self.assertIn("printable", msg.lower())

    def test_mixed_printable_and_non_printable(self):
        # Has at least one printable character — should pass
        ok, _ = validate_input("hello\x00")
        self.assertTrue(ok)

    def test_special_chars_valid(self):
        ok, _ = validate_input("Hello%20World!@#")
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
