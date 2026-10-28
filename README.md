# Cybersecurity Portfolio

A hands-on portfolio demonstrating practical cybersecurity skills, Python security automation, log analysis, and threat detection.

## Technical Skills

- Security Operations Center (SOC)
- Security Information and Event Management (SIEM) concepts
- Python for Security Automation
- Log Analysis and Threat Detection
- Incident Response
- Networking Fundamentals
- Risk Management and Security Compliance

## Projects

### Security Log Analyzer

**Technologies:** Python, JSON, unittest

A Python tool that analyzes authentication logs, detects suspicious login activity, and generates security alerts and reports.

**Features**
- Detects repeated failed logins within a rolling five-minute window.
- Assigns MEDIUM and HIGH severity to detected scenarios.
- Identifies successful logins following repeated failures.
- Skips malformed log entries, invalid timestamps, and unexpected statuses.
- Generates a human-readable security report.
- Exports structured alerts to JSON.
- Includes recommendations and MITRE ATT&CK mapping for brute-force activity.
- Includes automated tests for detection logic and input validation.

**Project files**
- `log_analyzer.py` — detection and reporting logic.
- `login.log` — sample authentication events.
- `security_report.txt` — generated report.
- `security_alerts.json` — structured alerts.
- `test_log_analyzer.py` — automated tests.

**Run the analyzer**

```bash
cd security-log-analyzer
python3 log_analyzer.py

**Run the tests**

From the portfolio folder, run:

`cd security-log-analyzer && python3 -m unittest -v test_log_analyzer.py`

The test suite contains 14 tests covering alert severity, suspicious login patterns, malformed records, independent IP addresses, and JSON alert validation.
### Threat Intelligence IP Enrichment Tool

**Technologies:** Python, JSON, unittest

A Python tool that validates IP addresses, checks them against a local sample threat-intelligence database, classifies results by severity, and generates a JSON investigation report.

**Features**
- Validates IPv4 and IPv6 addresses.
- Classifies sample records as HIGH, MEDIUM, or LOW severity.
- Handles invalid and unknown IP addresses.
- Provides investigation recommendations.
- Exports results to `threat_report.json`.
- Includes nine automated tests.

**Important limitation:** The database uses simulated records and documentation-only IP addresses. It does not perform live threat-intelligence lookups, and confidence values are illustrative.

**Run the tool**
```bash
cd threat-intel-enrichment
python3 threat_intel.py
```

**Run the tests**
```bash
python3 -m unittest -v test_threat_intel.py
```
## Certifications

- ISC2 Certified in Cybersecurity (CC)
- CompTIA Security+

## Career Goal

To build practical expertise in Security Operations Center (SOC) analysis, threat detection, security automation, and incident response.
