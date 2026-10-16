from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
import json


TIME_WINDOW = timedelta(minutes=5)
ALERT_THRESHOLD = 3
HIGH_SEVERITY_THRESHOLD = 5


def analyze_logins(filename):
    failed_attempts = Counter()
    successful_logins = Counter()
    recent_failures = defaultdict(deque)
    alerts = []
    total_records = 0

    print("\n=== CYBERSECURITY LOG ANALYZER ===")

    with open(filename, "r", encoding="utf-8") as log_file:
        for line in log_file:
            parts = line.strip().split()

            if len(parts) != 4:
                continue

            date, time, ip_address, result = parts

            try:
                timestamp = datetime.strptime(
                    f"{date} {time}", "%Y-%m-%d %H:%M:%S"
                )
            except ValueError:
                continue

            if result not in ("SUCCESS", "FAILED"):
                continue

            total_records += 1
            failures = recent_failures[ip_address]

            while failures and timestamp - failures[0] > TIME_WINDOW:
                failures.popleft()

            print(f"{timestamp} | {ip_address} | {result}")

            if result == "FAILED":
                failed_attempts[ip_address] += 1
                failures.append(timestamp)
                count = len(failures)

                if count == ALERT_THRESHOLD:
                    alerts.append({
                        "type": "Repeated Failed Logins",
                        "severity": "MEDIUM",
                        "ip": ip_address,
                        "count": count,
                        "time": timestamp,
                        "recommendation": (
                            "Investigate the source IP and review "
                            "authentication logs."
                        ),

                         "recommendation": (
    "Investigate the source IP and review authentication logs."
),
"mitre_attack": {
    "technique_id": "T1110",
    "technique_name": "Brute Force"
},




                    })

                elif count == HIGH_SEVERITY_THRESHOLD:
                    alerts.append({
                        "type": "Possible Brute-Force Attack",
                        "severity": "HIGH",
                        "ip": ip_address,
                        "count": count,
                        "time": timestamp,
                        "recommendation": (
                            "Investigate immediately and consider "
                            "blocking the source IP."
                        ),
                    })

            elif result == "SUCCESS":
                successful_logins[ip_address] += 1

                if len(failures) >= ALERT_THRESHOLD:
                    alerts.append({
                        "type": "Successful Login After Repeated Failures",
                        "severity": "HIGH",
                        "ip": ip_address,
                        "count": len(failures),
                        "time": timestamp,
                        "recommendation": (
                            "Verify whether the login was legitimate "
                            "and investigate possible account compromise."
                        ),
                         "mitre_attack": {
                             "technique_id": "T1110",
                             "technique_name": "Brute Force"
                    },
                    })

    print(f"\nTotal login records: {total_records}")
    print("Successful logins:", dict(successful_logins))
    print("Failed login attempts:", dict(failed_attempts))

    report = [
        "CYBERSECURITY LOG ANALYSIS REPORT",
        "=" * 40,
        f"Total login records: {total_records}",
        "",
        "SUCCESSFUL LOGINS:",
    ]

    if successful_logins:
        for ip, count in successful_logins.items():
            report.append(f"{ip}: {count}")
    else:
        report.append("None")

    report.extend(["", "FAILED LOGIN ATTEMPTS:"])

    if failed_attempts:
        for ip, count in failed_attempts.items():
            report.append(f"{ip}: {count}")
    else:
        report.append("None")

    report.extend(["", "SECURITY ALERTS:", "=" * 40])

    if not alerts:
        report.append("No security alerts detected.")
    else:
        for alert in alerts:
            report.extend([
                f"Alert type: {alert['type']}",
                f"Severity: {alert['severity']}",
                f"Source IP: {alert['ip']}",
                f"Related failed logins: {alert['count']}",
                f"Detection time: {alert['time']}",
                f"Recommendation: {alert['recommendation']}",
                "-" * 40,
            ])

    with open("security_report.txt", "w", encoding="utf-8") as report_file:
        report_file.write("\n".join(report) + "\n")

    json_alerts = []

    for index, alert in enumerate(alerts, start=1):
        json_alert = alert.copy()
        json_alert["alert_id"] = f"ALERT-{index:04d}"
        json_alert["time"] = alert["time"].isoformat()
        json_alerts.append(json_alert)

    with open("security_alerts.json", "w", encoding="utf-8") as json_file:
        json.dump(json_alerts, json_file, indent=4)

    print("\nSecurity report saved to security_report.txt")
    print("Structured alerts saved to security_alerts.json")
    print(f"Total security alerts: {len(alerts)}")
    return alerts

if __name__ == "__main__":
    analyze_logins("login.log")
