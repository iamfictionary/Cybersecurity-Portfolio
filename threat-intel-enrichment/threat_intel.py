import ipaddress
import json
from datetime import datetime, timezone


THREAT_DATABASE = {
    "192.0.2.10": {
        "reputation": "malicious",
        "threat_type": "Brute-force activity",
        "confidence": 95,
    },
    "198.51.100.25": {
        "reputation": "suspicious",
        "threat_type": "Repeated connection attempts",
        "confidence": 65,
    },
    "203.0.113.50": {
        "reputation": "clean",
        "threat_type": "No known threats in sample data",
        "confidence": 10,
    },
}


def validate_ip(address):
    """Return True if the supplied value is a valid IP address."""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def enrich_ip(address):
    """Return a threat-intelligence assessment for one IP address."""
    if not validate_ip(address):
        return {
            "ip": address,
            "severity": "INVALID",
            "reputation": "unknown",
            "threat_type": "Invalid IP address",
            "confidence": 0,
            "recommendation": "Check the IP address format before investigating.",
        }

    record = THREAT_DATABASE.get(
        address,
        {
            "reputation": "unknown",
            "threat_type": "Not found in sample threat data",
            "confidence": 0,
        },
    )

    severity_by_reputation = {
        "malicious": "HIGH",
        "suspicious": "MEDIUM",
        "clean": "LOW",
        "unknown": "UNCLASSIFIED",
    }

    recommendations = {
        "malicious": "Investigate related events and consider blocking the IP according to your organization's procedures.",
        "suspicious": "Review related logs and gather additional evidence before taking action.",
        "clean": "No known threat in this sample database; continue normal monitoring.",
        "unknown": "Check an approved threat-intelligence source and review relevant security logs.",
    }

    reputation = record["reputation"]

    return {
        "ip": address,
        "severity": severity_by_reputation[reputation],
        "reputation": reputation,
        "threat_type": record["threat_type"],
        "confidence": record["confidence"],
        "recommendation": recommendations[reputation],
    }


def main():
    print("Threat Intelligence IP Enrichment Tool")
    print("Enter an IP address, or type 'quit' to exit.")

    results = []

    while True:
        address = input("\nIP address: ").strip()

        if address.lower() == "quit":
            break

        result = enrich_ip(address)
        results.append(result)

        print(json.dumps(result, indent=2))

    if results:
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source": "Local sample threat-intelligence database",
            "results": results,
        }

        with open("threat_report.json", "w", encoding="utf-8") as report_file:
            json.dump(report, report_file, indent=2)

        print(f"\nSaved {len(results)} result(s) to threat_report.json")


if __name__ == "__main__":
    main()
