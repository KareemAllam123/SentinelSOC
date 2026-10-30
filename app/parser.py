from pathlib import Path
from datetime import datetime
import ipaddress


def parse_log_line(line):
    """
    Converts one authentication log line into a dictionary.

    Returns None if the line is invalid.
    """

    parts = line.strip().split()

    if len(parts) != 5:
        return None

    date, time, event_type, user_field, ip_field = parts

    if event_type not in ("FAILED_LOGIN", "SUCCESS_LOGIN"):
        return None

    if not user_field.startswith("user="):
        return None

    if not ip_field.startswith("ip="):
        return None

    username = user_field.split("=", 1)[1]
    ip_address = ip_field.split("=", 1)[1]

    if not username or not ip_address:
        return None

    try:
        timestamp = datetime.strptime(
            f"{date} {time}",
            "%Y-%m-%d %H:%M:%S"
        )

        ipaddress.ip_address(ip_address)

    except ValueError:
        return None

    return {
        "timestamp": timestamp,
        "event_type": event_type,
        "username": username,
        "ip_address": ip_address
    }

def read_log_file(file_path):
    """
    Reads a log file and returns valid security events.
    """

    events = []
    invalid_lines = 0

    path = Path(file_path)

    if not path.exists():
        print(f"Error: Log file not found: {file_path}")
        return events, invalid_lines

    with path.open("r", encoding="utf-8") as file:

        for line_number, line in enumerate(file, start=1):

            if not line.strip():
                continue

            event = parse_log_line(line)

            if event is not None:
                events.append(event)

            else:
                invalid_lines += 1

                print(
                    f"Warning: Invalid log entry "
                    f"at line {line_number}"
                )

    return events, invalid_lines