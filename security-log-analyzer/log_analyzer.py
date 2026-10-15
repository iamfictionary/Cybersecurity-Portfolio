
from collections import Counter

ALERT_THRESHOLD = 3


def analyze_logins(filename):
    failed_attempts = Counter()
    successful_logins = Counter()
    total_records = 0

    print("\n=== CYBERSECURITY LOG ANALYZER ===")

    with open(filename, "r") as log_file:
        for line in log_file:
            parts = line.strip().split()

            if len(parts) != 4:
                continue

            date, time, ip_address, result = parts
            timestamp = f"{date} {time}"
            total_records += 1

            print(f"{timestamp} | {ip_address} | {result}")

            if result == "FAILED":
                failed_attempts[ip_address] += 1
            elif result == "SUCCESS":
                successful_logins[ip_address] += 1

    print(f"\nTotal login records: {total_records}")

    print("\nSuccessful logins by IP address:")
    for ip_address, count in successful_logins.items():
        print(f"{ip_address}: {count} successful logins")

    print("\nFailed login attempts by IP address:")
    for ip_address, count in failed_attempts.items():
        print(f"{ip_address}: {count} failed attempts")

        if count >= ALERT_THRESHOLD:
            print(f"  ALERT: Suspicious activity from {ip_address}!")


if __name__ == "__main__":
    analyze_logins("login.log")

