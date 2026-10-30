from collections import defaultdict


def analyze_authentication_events(events):
    """
    Analyzes authentication events and returns statistics.
    """

    total_events = len(events)

    failed_logins = 0
    successful_logins = 0

    ip_statistics = defaultdict(
        lambda: {
            "failed": 0,
            "successful": 0,
            "total": 0
        }
    )

    for event in events:

        ip_address = event["ip_address"]
        event_type = event["event_type"]

        ip_statistics[ip_address]["total"] += 1

        if event_type == "FAILED_LOGIN":

            failed_logins += 1
            ip_statistics[ip_address]["failed"] += 1

        elif event_type == "SUCCESS_LOGIN":

            successful_logins += 1
            ip_statistics[ip_address]["successful"] += 1

    # Calculate failed-login percentage
    failed_login_rate = (
        (failed_logins / total_events) * 100
        if total_events > 0 else 0
    )

    return {
        "total_events": total_events,
        "failed_logins": failed_logins,
        "failed_login_rate": failed_login_rate,
        "successful_logins": successful_logins,
        "unique_ips": len(ip_statistics),
        "ip_statistics": dict(ip_statistics)
    }


def display_report(statistics, invalid_lines):
    """
    Displays a formatted authentication analysis report.
    """

    print("\n" + "=" * 55)
    print("             SentinelSOC Log Analyzer")
    print("=" * 55)

    print("\nAUTHENTICATION SUMMARY")
    print("-" * 55)

    print(f"Total Events:       {statistics['total_events']}")
    print(f"Failed Logins:      {statistics['failed_logins']}")
    print(f"Successful Logins:  {statistics['successful_logins']}")
    print(f"Failed Login Rate:  {statistics['failed_login_rate']:.2f}%")
    print(f"Unique IPs:         {statistics['unique_ips']}")
    print(f"Invalid Log Lines:  {invalid_lines}")

    print("\nIP ADDRESS ACTIVITY")
    print("-" * 55)

    for ip_address, data in sorted(
        statistics["ip_statistics"].items()
    ):

        print(f"\nIP Address: {ip_address}")
        print(f"  Total Events:      {data['total']}")
        print(f"  Failed Logins:     {data['failed']}")
        print(f"  Successful Logins: {data['successful']}")

    print("\n" + "=" * 55)
    print("             Analysis Complete")
    print("=" * 55)