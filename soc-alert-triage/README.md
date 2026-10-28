# SOC Alert Triage and Prioritization Tool

## Overview
A Python learning project that classifies sample security alerts by severity, explains why each alert matters, and recommends an appropriate next step for investigation.

## Features
- Classifies known alert types as Critical, High, Medium, or Low.
- Marks unsupported alert types as Unclassified for manual review.
- Provides a reason and recommended action for each alert.
- Generates a JSON triage report.
- Includes seven automated unit tests.

## Technologies
- Python 3
- JSON
- unittest
- Datetime and timezone handling

## How to Run
Run the sample alerts:

`python3 alert_triage.py`

Run the automated tests:

`python3 -m unittest -v test_alert_triage.py`

## Limitations
This project uses illustrative sample alerts and predefined demonstration rules. It does not connect to a SIEM, perform live threat intelligence lookups, or automatically block activity. Severity assignments are examples and should be adapted to an organization's incident response policies.

## Skills Demonstrated
- Security alert triage
- Severity classification
- Investigation recommendations
- JSON reporting
- Python development and unit testing