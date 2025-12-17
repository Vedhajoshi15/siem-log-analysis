import re
import csv
from collections import defaultdict

LOG_FILE = "logs/auth.log"
THRESHOLD = 3
OUTPUT_FILE = "report.csv"

failed_logins = defaultdict(int)

with open(LOG_FILE, "r") as file:
    for line in file:
        if "Failed password" in line:
            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                ip = ip_match.group(1)
                failed_logins[ip] += 1

print("=== SIEM LOGIN FAILURE REPORT ===")

with open(OUTPUT_FILE, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["IP Address", "Failed Attempts", "Alert"])

    for ip, count in failed_logins.items():
        alert = "YES" if count >= THRESHOLD else "NO"
        print(f"IP Address: {ip} | Failed Attempts: {count}")
        if alert == "YES":
            print(f"⚠️ ALERT: Possible brute-force attack detected from {ip}")

        writer.writerow([ip, count, alert])

print(f"\nReport saved to {OUTPUT_FILE}")
print("=== END REPORT ===")
