
import unittest

from analysis.validators import validate_url


class URLValidationTests(unittest.TestCase):

    def test_valid_https_url(self):
        result = validate_url("https://example.com")
        self.assertEqual(result, "https://example.com")

    def test_valid_http_url(self):
        result = validate_url("http://example.com/login")
        self.assertEqual(result, "http://example.com/login")

    def test_empty_url(self):
        with self.assertRaises(ValueError):
            validate_url("")

    def test_missing_scheme(self):
        with self.assertRaises(ValueError):
            validate_url("example.com")

    def test_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            validate_url("ftp://example.com")

    def test_missing_hostname(self):
        with self.assertRaises(ValueError):
            validate_url("https:///login")

    def test_whitespace(self):
        with self.assertRaises(ValueError):
            validate_url("https://example .com")

    def test_invalid_port(self):
        with self.assertRaises(ValueError):
            validate_url("https://example.com:99999")

    def test_invalid_hostname(self):
        with self.assertRaises(ValueError):
            validate_url("https://example..com")


if __name__ == "__main__":
    unittest.main()
