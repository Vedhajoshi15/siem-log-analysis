import re
from collections import defaultdict

LOG_FILE = "logs/auth.log"
THRESHOLD = 3  # brute-force alert threshold

failed_logins = defaultdict(int)

with open(LOG_FILE, "r") as file:
    for line in file:
        if "Failed password" in line:
            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                ip = ip_match.group(1)
                failed_logins[ip] += 1

print("=== SIEM LOGIN FAILURE REPORT ===")

for ip, count in failed_logins.items():
    print(f"IP Address: {ip} | Failed Attempts: {count}")
    if count >= THRESHOLD:
        print(f"⚠️ ALERT: Possible brute-force attack detected from {ip}")

print("=== END REPORT ===")
