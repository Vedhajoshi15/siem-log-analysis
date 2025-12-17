# SIEM Log Analysis (Python)

A simple SIEM-style log analyzer that scans Linux `auth.log` data to identify suspicious SSH login activity and flag potential brute-force attacks.

## Features
- Parses SSH authentication logs (`auth.log`)
- Counts failed login attempts by source IP
- Raises an alert when attempts exceed a threshold (default: 3)

## Tech Stack
- Python 3
- Regex-based parsing
- Works with sample logs included in this repo

## How to Run
1. Clone the repo:
   ```bash
   git clone https://github.com/Vedhajoshi15/siem-log-analysis.git
   cd siem-log-analysis
