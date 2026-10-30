from datetime import datetime
from pathlib import Path

from app.parser import read_log_file
from app.analyzer import (
    analyze_authentication_events,
    display_report
)


BASE_DIR = Path(__file__).resolve().parent.parent

LOG_FILE = (
    BASE_DIR
    / "data"
    / "sample_logs"
    / "authentication.log"
)


def display_banner():

    print("=" * 55)
    print("                    SentinelSOC")
    print("        Security Monitoring & Threat Detection")
    print("=" * 55)


def initialize_system():

    print("\nInitializing SentinelSOC...")

    current_time = datetime.now()

    print(f"System started at: {current_time}")
    print("System Status: ONLINE")
    print("Monitoring Mode: DEVELOPMENT")
    print("Log Source: Local Authentication Logs")
    print("Project Version: 0.2.0")

    print("\nInitialization complete.")


def main():

    display_banner()

    initialize_system()

    print("\nLoading authentication logs...")

    if not LOG_FILE.is_file():
        print(f"Error: Log file not found: {LOG_FILE}")
        return

    events, invalid_lines = read_log_file(LOG_FILE)

    print(f"Successfully loaded {len(events)} valid events.")

    statistics = analyze_authentication_events(events)

    display_report(statistics, invalid_lines)


if __name__ == "__main__":
    main()