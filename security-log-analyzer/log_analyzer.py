from collections import Counter

# Sample login records for testing
login_records = [
    ("192.168.1.10", "FAILED"),
    ("192.168.1.10", "FAILED"),
    ("192.168.1.10", "FAILED"),
    ("192.168.1.25", "SUCCESS"),
    ("192.168.1.10", "FAILED"),
    ("192.168.1.30", "FAILED"),
    ("192.168.1.25", "SUCCESS"),
]

# Number of failed logins that triggers an alert
ALERT_THRESHOLD = 3


def analyze_logins(records):
    failed_attempts = Counter()

    for ip_address, result in records:
        if result == "FAILED":
            failed_attempts[ip_address] += 1

    print("\n=== CYBERSECURITY LOG ANALYZER ===")
    print(f"Total login records: {len(records)}")
    print("\nFailed login attempts by IP address:")

    for ip_address, count in failed_attempts.items():
        print(f"{ip_address}: {count} failed attempts")

        if count >= ALERT_THRESHOLD:
            print(f"  ALERT: Suspicious activity from {ip_address}!")


if __name__ == "__main__":
    analyze_logins(login_records)
