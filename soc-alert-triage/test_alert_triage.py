import unittest
from alert_triage import triage_alert


class TestAlertTriage(unittest.TestCase):

    def test_failed_logins_are_high(self):
        result = triage_alert({"alert_id": "SOC-001", "type": "multiple_failed_logins"})
        self.assertEqual(result["severity"], "HIGH")

    def test_malware_is_critical(self):
        result = triage_alert({"alert_id": "SOC-002", "type": "malware_detected"})
        self.assertEqual(result["severity"], "CRITICAL")

    def test_outbound_traffic_is_medium(self):
        result = triage_alert({"alert_id": "SOC-003", "type": "unusual_outbound_traffic"})
        self.assertEqual(result["severity"], "MEDIUM")

    def test_policy_violation_is_low(self):
        result = triage_alert({"alert_id": "SOC-004", "type": "policy_violation"})
        self.assertEqual(result["severity"], "LOW")

    def test_unknown_alert_is_unclassified(self):
        result = triage_alert({"alert_id": "SOC-005", "type": "unknown_event"})
        self.assertEqual(result["severity"], "UNCLASSIFIED")

    def test_recommendation_is_included(self):
        result = triage_alert({"alert_id": "SOC-006", "type": "malware_detected"})
        self.assertTrue(result["recommendation"])

    def test_alert_id_is_preserved(self):
        result = triage_alert({"alert_id": "SOC-007", "type": "policy_violation"})
        self.assertEqual(result["alert_id"], "SOC-007")


if __name__ == "__main__":
    unittest.main()
