from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta

ALERT_THRESHOLD = 3
HIGH_SEVERITY_THRESHOLD = 5
TIME_WINDOW = timedelta(minutes=5)


def analyze_logins(filename):
    failed_attempts = Counter()
    successful_logins = Counter()
    recent_failures = defaultdict(deque)
    alerts = []
    total_records = 0

    print("\n=== CYBERSECURITY LOG ANALYZER ===")

    with open(filename, "r") as log_file:
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
                print(f"Skipping invalid timestamp: {line.strip()}")
                continue

            if result not in ("SUCCESS", "FAILED"):
                continue

            total_records += 1
            failures = recent_failures[ip_address]

            while failures and timestamp - failures[0] > TIME_WINDOW:
                failures.popleft()

            print(f"{timestamp} | {ip_address} | {result}")

            if result == "SUCCESS":
                successful_logins[ip_address] += 1

                if len(failures) >= ALERT_THRESHOLD:
                    alerts.append({
                        "ip": ip_address,
                        "severity": "HIGH",
                        "time": timestamp,
                        "count": len(failures),
                        "type": "Successful login after repeated failures",
                        "recommendation": (
                            "Investigate the account and source IP, review "
                            "nearby authentication events, and verify whether "
                            "the login was legitimate."
                        ),
                    })

                    print(
                        f"  ALERT: Successful login from {ip_address} "
                        "after repeated failed attempts!"
                    )

            elif result == "FAILED":
                failed_attempts[ip_address] += 1
                failures.append(timestamp)
                count = len(failures)

                if count == ALERT_THRESHOLD:
                    alerts.append({
                        "ip": ip_address,
                        "severity": "MEDIUM",
                        "time": timestamp,
                        "count": count,
                        "type": "Repeated failed logins",
                        "recommendation": (
                            "Review authentication logs and investigate "
                            "the source IP for related suspicious activity."
                        ),
                    })

                elif count == HIGH_SEVERITY_THRESHOLD:
                    alerts.append({
                        "ip": ip_address,
                        "severity": "HIGH",
                        "time": timestamp,
                        "count": count,
                        "type": "Repeated failed logins - high threshold",
                        "recommendation": (
                            "Prioritize investigation, check for successful "
                            "logins, and consider containment if malicious "
                            "activity is confirmed."
                        ),
                    })

    print(f"\nTotal login records: {total_records}")

    print("\nSuccessful logins by IP address:")
    for ip, count in successful_logins.items():
        print(f"{ip}: {count} successful logins")

    print("\nFailed login attempts by IP address:")
    for ip, count in failed_attempts.items():
        print(f"{ip}: {count} failed attempts")

    print("\nSecurity alerts:")
    if not alerts:
        print("No security alerts detected.")
    else:
        for alert in alerts:
            print(
                f"[{alert['severity']}] {alert['type']} - "
                f"{alert['ip']} at {alert['time']}"
            )
            print(f"  Recommendation: {alert['recommendation']}")

    report = [
        "CYBERSECURITY LOGIN ANALYSIS REPORT",
        "=" * 40,
        f"Report generated: {datetime.now()}",
        f"Total login records: {total_records}",
        "",
        "SUCCESSFUL LOGINS BY IP:",
    ]

    for ip, count in successful_logins.items():
        report.append(f"{ip}: {count} successful logins")

    report.extend(["", "FAILED LOGIN ATTEMPTS BY IP:"])

    for ip, count in failed_attempts.items():
        report.append(f"{ip}: {count} failed attempts")

    report.extend(["", "SECURITY ALERTS:"])

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

    with open("security_report.txt", "w") as report_file:
        report_file.write("\n".join(report) + "\n")

    print("\nSecurity report saved to security_report.txt")


if __name__ == "__main__":

       analyze_logins("login.log") 
