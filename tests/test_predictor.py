
import unittest

from analysis.predictor import predict_url


class PredictorTests(unittest.TestCase):

    def test_benign_url(self):
        result = predict_url("https://www.example.com")

        self.assertIn(
            result["prediction"],
            ["benign", "phishing"]
        )

        self.assertIn(
            result["risk"],
            ["Low", "Medium", "High"]
        )

        self.assertGreaterEqual(
            result["phishing_probability"], 0
        )

        self.assertLessEqual(
            result["phishing_probability"], 1
        )

    def test_phishing_style_url(self):
        result = predict_url(
            "http://secure-login.example.com/account/verify"
        )

        self.assertIn(
            result["prediction"],
            ["benign", "phishing"]
        )

        self.assertIn(
            result["risk"],
            ["Low", "Medium", "High"]
        )

    def test_feature_order(self):
        result = predict_url("https://example.com")

        self.assertEqual(
            list(result["features"].keys()),
            [
                "uses_https",
                "hostname_is_ip",
                "url_length",
                "subdomain_count",
                "suspicious_keyword_count",
                "special_char_count",
                "encoded_char_count",
                "has_at_symbol",
                "brand_misuse",
            ]
        )


if __name__ == "__main__":
    unittest.main()
