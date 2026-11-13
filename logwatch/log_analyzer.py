import re
import ipaddress
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from pathlib import Path

# ==========================================
# LOGWATCH PRO
# TIME-BASED SECURITY LOG ANALYZER
# ==========================================

LOG_FILE = Path("logwatch/logs/auth.log")
REPORT_FILE = Path("logwatch/reports/security_report.txt")

# Detection configuration

MEDIUM_THRESHOLD = 3
HIGH_THRESHOLD = 5
CRITICAL_THRESHOLD = 10

ONE_MINUTE = timedelta(minutes=1)
FIVE_MINUTES = timedelta(minutes=5)
CORRELATION_WINDOW = timedelta(minutes=10)

# This parser supports standard Linux SSH authentication logs.
LOG_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r".*?(?P<event>Failed password|Accepted password)"
    r".*?from\s+(?P<ip>\S+)"
)

# ==========================================
# PARSE LOG FILE
# ==========================================

def read_logs():

    events = []
    invalid_lines = 0

    if not LOG_FILE.exists():
        print("ERROR: Log file not found:", LOG_FILE)
        return None

    with LOG_FILE.open("r", encoding="utf-8") as file:

        for line_number, line in enumerate(file, start=1):

            match = LOG_PATTERN.search(line)

            if not match:
                continue

            timestamp_text = match.group("timestamp")
            event_type = match.group("event")
            ip_address = match.group("ip")

            try:
                # Standard syslog timestamps do not contain a year.
                timestamp = datetime.strptime(
                    f"{datetime.now().year} {timestamp_text}",
                    "%Y %b %d %H:%M:%S"
                )

                ipaddress.ip_address(ip_address)

            except ValueError:
                invalid_lines += 1
                print("WARNING: Invalid entry at line", line_number)
                continue

            events.append({
                "time": timestamp,
                "event": event_type,
                "ip": ip_address
            })

    events.sort(key=lambda item: item["time"])

    return events, invalid_lines


# ==========================================
# TIME-BASED DETECTION
# ==========================================

def count_within_window(failures, current_time, window):

    start_time = current_time - window

    return sum(
        1 for event in failures
        if start_time <= event["time"] <= current_time
    )


def analyze_ip(ip, ip_events):

    failures = [
        event for event in ip_events
        if event["event"] == "Failed password"
    ]

    successes = [
        event for event in ip_events
        if event["event"] == "Accepted password"
    ]

    max_one_minute = 0
    max_five_minutes = 0

    # Check every failed event as the end of a time window.

    for event in failures:

        current_time = event["time"]

        one_minute_count = count_within_window(
            failures,
            current_time,
            ONE_MINUTE
        )

        five_minute_count = count_within_window(
            failures,
            current_time,
            FIVE_MINUTES
        )

        max_one_minute = max(
            max_one_minute,
            one_minute_count
        )

        max_five_minutes = max(
            max_five_minutes,
            five_minute_count
        )

    # Determine severity using the highest applicable level.

    if max_five_minutes >= CRITICAL_THRESHOLD:

        severity = "CRITICAL"

    elif max_one_minute >= HIGH_THRESHOLD:

        severity = "HIGH"

    elif max_five_minutes >= MEDIUM_THRESHOLD:

        severity = "MEDIUM"

    elif len(failures) > 0:

        severity = "LOW"

    else:

        severity = "NONE"

    # Check for successful login within 10 minutes
    # after a failed login from the same IP.

    success_after_failure = False

    for success in successes:

        for failure in failures:

            time_difference = (
                success["time"] - failure["time"]
            )

            if timedelta(0) <= time_difference <= CORRELATION_WINDOW:

                success_after_failure = True
                break

        if success_after_failure:
            break

    return {
        "failed": len(failures),
        "successful": len(successes),
        "max_one_minute": max_one_minute,
        "max_five_minutes": max_five_minutes,
        "severity": severity,
        "success_after_failure": success_after_failure
    }


# ==========================================
# GENERATE INVESTIGATION REPORT
# ==========================================

def generate_report(results, total_events, invalid_lines):

    REPORT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with REPORT_FILE.open("w", encoding="utf-8") as report:

        report.write("LOGWATCH PRO - SECURITY REPORT\n")
        report.write("=" * 55 + "\n\n")

        report.write(f"Total recognized events: {total_events}\n")
        report.write(f"Invalid log entries: {invalid_lines}\n")
        report.write(f"Analyzed IP addresses: {len(results)}\n\n")

        report.write("IP ADDRESS INVESTIGATION\n")
        report.write("-" * 55 + "\n")

        for ip, data in results.items():

            report.write(f"\nIP Address: {ip}\n")
            report.write(f"Severity: {data['severity']}\n")
            report.write(f"Failed attempts: {data['failed']}\n")
            report.write(f"Successful attempts: {data['successful']}\n")

            report.write(
                f"Maximum failures in 1 minute: "
                f"{data['max_one_minute']}\n"
            )

            report.write(
                f"Maximum failures in 5 minutes: "
                f"{data['max_five_minutes']}\n"
            )

            report.write(
                f"Successful login after failure within 10 minutes: "
                f"{data['success_after_failure']}\n"
            )

            report.write("-" * 35 + "\n")

    print("\nReport generated:", REPORT_FILE)


# ==========================================
# MAIN PROGRAM
# ==========================================

def main():

    print("=" * 55)
    print("       LOGWATCH PRO - SECURITY ANALYZER")
    print("=" * 55)

    log_data = read_logs()

    if log_data is None:
        return

    events, invalid_lines = log_data

    if not events:
        print("\nNo recognized authentication events found.")
        return

    # Group events by source IP.

    ip_groups = defaultdict(list)

    for event in events:
        ip_groups[event["ip"]].append(event)

    # Analyze each IP address.

    results = {}

    for ip, ip_events in ip_groups.items():

        results[ip] = analyze_ip(ip, ip_events)

    # Display results.

    print("\n========== SECURITY SUMMARY ==========")

    print("Total recognized events:", len(events))

    print(
        "Total failed attempts:",
        sum(data["failed"] for data in results.values())
    )

    print(
        "Total successful attempts:",
        sum(data["successful"] for data in results.values())
    )

    print("Analyzed IP addresses:", len(results))

    print("\n========== IP INVESTIGATIONS ==========")

    for ip, data in results.items():

        print("\nIP Address:", ip)
        print("Severity:", data["severity"])
        print("Failed attempts:", data["failed"])

        print(
            "Maximum failures in 1 minute:",
            data["max_one_minute"]
        )

        print(
            "Maximum failures in 5 minutes:",
            data["max_five_minutes"]
        )

        if data["success_after_failure"]:

            print(
                "WARNING: Successful login followed "
                "a failed login within 10 minutes!"
            )

        print("-" * 40)

    # Count severity levels.

    severity_counts = Counter(
        data["severity"] for data in results.values()
    )

    print("\n========== ALERT SUMMARY ==========")

    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:

        print(
            level + ":",
            severity_counts.get(level, 0)
        )

    generate_report(results, len(events), invalid_lines)

    print("\nAnalysis completed successfully!")


if __name__ == "__main__":
    main()