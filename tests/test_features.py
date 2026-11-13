
import unittest

from analysis.features import extract_features, FEATURE_ORDER


class FeatureExtractionTests(unittest.TestCase):

    def test_feature_order(self):
        url = "https://example.com"
        features = extract_features(url)

        self.assertEqual(
            list(features.keys()),
            FEATURE_ORDER
        )

    def test_https_detection(self):
        features = extract_features("https://example.com")

        self.assertEqual(features["uses_https"], 1)

    def test_ip_address_detection(self):
        features = extract_features("http://192.0.2.1/login")

        self.assertEqual(features["hostname_is_ip"], 1)

    def test_subdomain_count(self):
        features = extract_features(
            "https://shop.example.com"
        )

        self.assertEqual(features["subdomain_count"], 1)

    def test_encoded_character_count(self):
        features = extract_features(
            "https://example.com/page%20name"
        )

        self.assertEqual(features["encoded_char_count"], 1)

    def test_at_symbol_detection(self):
        features = extract_features(
            "https://user@example.com"
        )

        self.assertEqual(features["has_at_symbol"], 1)

    def test_invalid_scheme(self):
        with self.assertRaises(ValueError):
            extract_features("ftp://example.com")

    def test_missing_hostname(self):
        with self.assertRaises(ValueError):
            extract_features("https:///page")

    def test_empty_url(self):
        with self.assertRaises(ValueError):
            extract_features("")


if __name__ == "__main__":
    unittest.main()
