import unittest
import tempfile
import os
import io
from contextlib import redirect_stdout
from log_analyzer import analyze_logins


class TestSecurityLogAnalyzer(unittest.TestCase):

    def run_test_log(self, log_contents):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_dir = os.getcwd()

            try:
                os.chdir(temp_dir)

                with open("test.log", "w", encoding="utf-8") as file:
                    file.write(log_contents)

                with redirect_stdout(io.StringIO()):
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

        self.assertTrue(
            any(alert["severity"] == "MEDIUM" for alert in alerts)
        )

    def test_five_failures_create_high_alert(self):
        log = "".join(
            f"2026-10-15 09:00:{second:02d} "
            "192.168.1.10 FAILED\n"
            for second in (0, 10, 20, 30, 40)
        )

        alerts = self.run_test_log(log)

        self.assertTrue(
            any(alert["severity"] == "HIGH" for alert in alerts)
        )

    def test_success_after_failures_creates_high_alert(self):
        log = (
            "2026-10-15 09:00:00 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:10 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:20 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:30 192.168.1.10 SUCCESS\n"
        )

        alerts = self.run_test_log(log)

        self.assertTrue(
            any(
                alert["type"]
                == "Successful Login After Repeated Failures"
                for alert in alerts
            )
        )

    def test_normal_successful_login_creates_no_alert(self):
        log = "2026-10-15 09:00:00 192.168.1.10 SUCCESS\n"

        alerts = self.run_test_log(log)

        self.assertEqual(alerts, [])

    def test_alert_contains_mitre_mapping(self):
        log = (
            "2026-10-15 09:00:00 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:10 192.168.1.10 FAILED\n"
            "2026-10-15 09:00:20 192.168.1.10 FAILED\n"
        )

        alerts = self.run_test_log(log)

        self.assertEqual(
            alerts[0]["mitre_attack"]["technique_id"], "T1110"
        )


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
if __name__ == "__main__":
    unittest.main()
