import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

from log_analyzer import analyze_logins


class TestSecurityLogAnalyzer(unittest.TestCase):
    def run_test_log(self, log):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_dir = os.getcwd()
            try:
                os.chdir(temp_dir)

                with open("test.log", "w", encoding="utf-8") as file:
                    file.write(log)

                with redirect_stdout(StringIO()):
                    alerts = analyze_logins("test.log")

                return alerts
            finally:
                os.chdir(original_dir)

    def test_three_failures_create_medium_alert(self):
        log = (
            "2026-10-15 09:00:00 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:15 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:30 192.168.1.10 FAILED\n"
        )
        alerts = self.run_test_log(log)
        self.assertTrue(any(alert["severity"] == "MEDIUM" for alert in alerts))

    def test_five_failures_create_high_alert(self):
        log = (
            "2026-10-15 09:00:00 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:15 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:30 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:45 192.168.1.10 FAILED\n"
            "2026-10-15 09:01:00 192.168.1.10 FAILED\n"
        )
        alerts = self.run_test_log(log)
        self.assertTrue(any(alert["severity"] == "HIGH" for alert in alerts))

    def test_success_after_failures_creates_high_alert(self):
        log = (
            "2026-10-15 09:00:00 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:15 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:30 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:45 192.168.1.10 SUCCESS\n"
        )
        alerts = self.run_test_log(log)
        self.assertTrue(any(alert["severity"] == "HIGH" for alert in alerts))

    def test_normal_successful_login_creates_no_alert(self):
        log = "2026-10-15 09:00:00 192.168.1.25 SUCCESS\n"
        alerts = self.run_test_log(log)
        self.assertEqual(alerts, [])

    def test_alert_contains_mitre_mapping(self):
        log = (
            "2026-10-15 09:00:00 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:15 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:30 192.168.1.10 FAILED\n"
        )
        alerts = self.run_test_log(log)
        self.assertEqual(alerts[0]["mitre_attack"]["technique_id"], "T1110")

    def test_three_failures_outside_five_minute_window_create_no_alert(self):
        log = (
            "2026-10-15 09:00:00 192.168.1.10 FAILED\n"
            "2026-10-15 09:05:01 192.168.1.10 FAILED\n"
            "2026-10-15 09:10:02 192.168.1.10 FAILED\n"
        )
        alerts = self.run_test_log(log)
        self.assertEqual(alerts, [])

    def test_failures_from_different_ips_are_counted_independently(self):
        log = (
            "2026-10-15 09:00:00 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:15 192.168.1.25 FAILED\n"
            "2026-10-15 09:00:30 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:45 192.168.1.25 FAILED\n"
        )
        alerts = self.run_test_log(log)
        self.assertEqual(alerts, [])

    def test_malformed_log_entries_do_not_crash_analyzer(self):
        log = (
            "this is not a valid log entry\n"
            "2026-10-15 09:00:00 192.168.1.10 FAILED\n"
            "not-a-date 192.168.1.10 FAILED\n"
        )
        alerts = self.run_test_log(log)
        self.assertEqual(alerts, [])

    def test_five_failures_create_high_severity_alert(self):
        log = (
            "2026-10-15 09:00:00 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:15 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:30 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:45 192.168.1.10 FAILED\n"
            "2026-10-15 09:01:00 192.168.1.10 FAILED\n"
        )
        alerts = self.run_test_log(log)
        self.assertTrue(any(alert["severity"] == "HIGH" for alert in alerts))

    def test_alert_ids_are_unique(self):
        log = (
            "2026-10-15 09:00:00 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:15 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:30 192.168.1.10 FAILED\n"
            "2026-10-15 09:01:00 192.168.1.25 FAILED\n"
            "2026-10-15 09:01:15 192.168.1.25 FAILED\n"
            "2026-10-15 09:01:30 192.168.1.25 FAILED\n"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            original_dir = os.getcwd()
            try:
                os.chdir(temp_dir)
                with open("test.log", "w", encoding="utf-8") as file:
                    file.write(log)
                with redirect_stdout(StringIO()):
                    analyze_logins("test.log")

                with open("security_alerts.json", encoding="utf-8") as file:
                    json_alerts = json.load(file)
            finally:
                os.chdir(original_dir)

        alert_ids = [alert["alert_id"] for alert in json_alerts]
        self.assertGreaterEqual(len(alert_ids), 2)
        self.assertEqual(len(alert_ids), len(set(alert_ids)))

    def test_json_alerts_contain_required_fields(self):
        log = (
            "2026-10-15 09:00:00 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:15 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:30 192.168.1.10 FAILED\n"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            original_dir = os.getcwd()
            try:
                os.chdir(temp_dir)

                with open("test.log", "w", encoding="utf-8") as file:
                    file.write(log)

                with redirect_stdout(StringIO()):
                    analyze_logins("test.log")

                with open("security_alerts.json", encoding="utf-8") as file:
                    json_alerts = json.load(file)
            finally:
                os.chdir(original_dir)

        self.assertTrue(json_alerts)

        required_fields = {
            "alert_id",
            "time",
            "severity",
            "type",
            "ip",
            "count",
            "recommendation",
        }

        for alert in json_alerts:
            self.assertTrue(required_fields.issubset(alert.keys()))

    def test_unexpected_status_is_ignored(self):
        log = (
            "2026-10-15 09:00:00 192.168.1.10 UNKNOWN\\n"
        )
        alerts = self.run_test_log(log)
        self.assertEqual(alerts, [])


    def test_incomplete_log_entry_is_ignored(self):
        log = (
            "2026-10-15 09:00:00 192.168.1.10 FAILED\\n"
            "2026-10-15 09:00:15 192.168.1.10\\n"
        )
        alerts = self.run_test_log(log)
        self.assertTrue(
            all(alert["ip"] != "192.168.1.10" for alert in alerts)
            or alerts == []
        )


    def test_attack_from_one_ip_does_not_trigger_alert_for_another(self):
        log = (
            "2026-10-15 09:00:00 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:10 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:20 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:30 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:40 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:15 192.168.1.25 FAILED\n"
            "2026-10-15 09:00:25 192.168.1.25 FAILED\n"
        )
        alerts = self.run_test_log(log)
        self.assertTrue(
            any(
                alert["ip"] == "192.168.1.10"
                and alert["severity"] == "HIGH"
                for alert in alerts
            )
        )
        self.assertFalse(
            any(alert["ip"] == "192.168.1.25" for alert in alerts)
        )

if __name__ == "__main__":
    unittest.main()
