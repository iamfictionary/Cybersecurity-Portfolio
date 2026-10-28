import json
from datetime import datetime, timezone


def triage_alert(alert):
    alert_type = alert.get("type", "").strip().lower()

    rules = {
        "multiple_failed_logins": {
            "severity": "HIGH",
            "reason": "Repeated failed login attempts may indicate a brute-force attack.",
            "recommendation": "Review authentication logs, verify the source IP, and check for a successful login."
        },
        "malware_detected": {
            "severity": "CRITICAL",
            "reason": "A malware detection may indicate a compromised system.",
            "recommendation": "Follow incident response procedures and investigate or isolate the affected host according to policy."
        },
        "unusual_outbound_traffic": {
            "severity": "MEDIUM",
            "reason": "Unusual outbound traffic may indicate suspicious communication or data transfer.",
            "recommendation": "Review destination, volume, timing, and endpoint activity to determine whether the traffic is expected."
        },
        "policy_violation": {
            "severity": "LOW",
            "reason": "An activity may have violated an internal security policy.",
            "recommendation": "Review the event and applicable policy to determine whether further investigation is required."
        }
    }

    result = rules.get(alert_type)

    if result is None:
        result = {
            "severity": "UNCLASSIFIED",
            "reason": "No triage rule exists for this alert type.",
            "recommendation": "Review the alert manually and create an approved rule if appropriate."
        }

    return {
        "alert_id": alert.get("alert_id", "UNKNOWN"),
        "type": alert.get("type", "unknown"),
        "severity": result["severity"],
        "reason": result["reason"],
        "recommendation": result["recommendation"]
    }


def main():
    sample_alerts = [
        {
            "alert_id": "SOC-001",
            "type": "multiple_failed_logins",
            "source_ip": "192.0.2.25"
        },
        {
            "alert_id": "SOC-002",
            "type": "malware_detected",
            "source_ip": "198.51.100.15"
        },
        {
            "alert_id": "SOC-003",
            "type": "unusual_outbound_traffic",
            "source_ip": "203.0.113.40"
        },
        {
            "alert_id": "SOC-004",
            "type": "policy_violation",
            "source_ip": "192.0.2.50"
        },
        {
            "alert_id": "SOC-005",
            "type": "unknown_event",
            "source_ip": "192.0.2.75"
        }
    ]

    results = [triage_alert(alert) for alert in sample_alerts]

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "note": "Training data only. Alerts and IP addresses are illustrative.",
        "total_alerts": len(results),
        "alerts": results
    }

    with open("triage_report.json", "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    print(json.dumps(report, indent=2))
    print("\nReport saved to triage_report.json")


if __name__ == "__main__":
    main()
