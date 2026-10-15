
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta

ALERT_THRESHOLD = 3
TIME_WINDOW = timedelta(minutes=5)


def analyze_logins(filename):
    failed_attempts = Counter()
    successful_logins = Counter()
    recent_failures = defaultdict(deque)
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

            total_records += 1
            print(f"{timestamp} | {ip_address} | {result}")

            if result == "SUCCESS":
                successful_logins[ip_address] += 1

            elif result == "FAILED":
                failed_attempts[ip_address] += 1
                failures = recent_failures[ip_address]

                while failures and timestamp - failures[0] > TIME_WINDOW:
                    failures.popleft()

                failures.append(timestamp)

                if len(failures) == ALERT_THRESHOLD:
                    print(
                        f"  ALERT: {ip_address} had "
                        f"{ALERT_THRESHOLD} failed logins within 5 minutes!"
                    )

    print(f"\nTotal login records: {total_records}")

    print("\nSuccessful logins by IP address:")
    for ip, count in successful_logins.items():
        print(f"{ip}: {count} successful logins")

    print("\nFailed login attempts by IP address:")
    for ip, count in failed_attempts.items():
        print(f"{ip}: {count} failed attempts")


if __name__ == "__main__":
    analyze_logins("login.log")

