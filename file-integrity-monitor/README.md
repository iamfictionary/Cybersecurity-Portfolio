# File Integrity Monitoring Tool

## Overview
A Python security tool that uses SHA-256 hashes to detect changes to monitored files by comparing them against a saved baseline.

## Features
- Calculates SHA-256 file hashes.
- Creates a baseline of monitored files.
- Detects added, modified, and deleted files.
- Generates JSON integrity reports.
- Includes automated unit tests.

## Technologies
- Python 3
- SHA-256
- JSON
- pathlib
- unittest

## How to Run
1. Run `python3 file_monitor.py`.
2. Choose option `1` to create a baseline.
3. Enter the directory you want to monitor.
4. Later, run the program again and choose option `2` to check for changes.

## Run Tests
Run `python3 -m unittest -v test_file_monitor.py`.

## Security Notes and Limitations
This is a learning project, not a production monitoring system. Protect the baseline from unauthorized changes. An attacker who can alter both the monitored files and the baseline may conceal changes. Checks are manual; real-time monitoring is not supported.

## Skills Demonstrated
- File integrity monitoring
- Cryptographic hashing
- Change detection
- JSON reporting
- Python unit testing
- Basic security validation