from datetime import datetime


def display_banner():
    print("=" * 50)
    print("           SentinelSOC")
    print("    Security Monitoring & Threat Detection")
    print("=" * 50)


def initialize_system():
    print("\nInitializing SentinelSOC...")

    current_time = datetime.now()

    print(f"System started at: {current_time}")
    print("System Status: ONLINE")
    print("Detection Engine: Not initialized")
    print("Database: Not connected")

    print("\nInitialization complete.")


def main():
    display_banner()
    initialize_system()


if __name__ == "__main__":
    main()