import unittest

from threat_intel import validate_ip, enrich_ip


class TestThreatIntel(unittest.TestCase):

    def test_valid_ipv4_address(self):
        self.assertTrue(validate_ip("192.0.2.10"))

    def test_valid_ipv6_address(self):
        self.assertTrue(validate_ip("2001:db8::1"))

    def test_invalid_ip_address(self):
        self.assertFalse(validate_ip("999.999.999.999"))

    def test_malicious_ip_has_high_severity(self):
        result = enrich_ip("192.0.2.10")
        self.assertEqual(result["severity"], "HIGH")
        self.assertEqual(result["reputation"], "malicious")

    def test_suspicious_ip_has_medium_severity(self):
        result = enrich_ip("198.51.100.25")
        self.assertEqual(result["severity"], "MEDIUM")
        self.assertEqual(result["reputation"], "suspicious")

    def test_clean_ip_has_low_severity(self):
        result = enrich_ip("203.0.113.50")
        self.assertEqual(result["severity"], "LOW")
        self.assertEqual(result["reputation"], "clean")

    def test_unknown_valid_ip_is_unclassified(self):
        result = enrich_ip("8.8.8.8")
        self.assertEqual(result["severity"], "UNCLASSIFIED")
        self.assertEqual(result["reputation"], "unknown")

    def test_invalid_ip_returns_invalid_severity(self):
        result = enrich_ip("999.999.999.999")
        self.assertEqual(result["severity"], "INVALID")
        self.assertEqual(result["threat_type"], "Invalid IP address")

    def test_result_contains_required_fields(self):
        result = enrich_ip("192.0.2.10")
        required_fields = {
            "ip",
            "severity",
            "reputation",
            "threat_type",
            "confidence",
            "recommendation",
        }
        self.assertTrue(required_fields.issubset(result.keys()))


if __name__ == "__main__":
    unittest.main()
