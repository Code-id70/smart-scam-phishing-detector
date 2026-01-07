import unittest
from analysis import analyze_message


class TestDetector(unittest.TestCase):
    def test_obvious_phishing(self):
        result = analyze_message("URGENT! Verify your account now!", "")
        self.assertEqual(result["risk_level"], "High")

    def test_normal_message(self):
        result = analyze_message("Hi, how are you?", "")
        self.assertEqual(result["risk_level"], "Low")

    def test_credential_harvesting(self):
        result = analyze_message("Please update your payment information", "")
        self.assertIn("credential", " ".join(result["explanations"]).lower())

    def test_suspicious_url(self):
        result = analyze_message("", "http://192.168.1.1/malicious")
        self.assertEqual(result["risk_level"], "High")

    def test_shortener_url(self):
        result = analyze_message("", "https://bit.ly/short")
        self.assertIn("shortener", " ".join(result["explanations"]).lower())


if __name__ == "__main__":
    unittest.main()
