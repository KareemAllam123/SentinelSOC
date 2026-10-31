from collections import defaultdict, deque
from datetime import timedelta


def detect_brute_force(events, threshold=5, window_seconds=60):
    """
    Detects possible brute-force attacks and successful
    logins following repeated failed attempts.

    Returns a list of security alerts.
    """

    if threshold < 1 or window_seconds <= 0:
        raise ValueError("Threshold and window must be positive.")

    alerts = []

    failed_attempts = defaultdict(deque)

    # Track when each IP/account combination triggered
    # a brute-force alert.
    active_brute_force = {}

    sorted_events = sorted(
        events,
        key=lambda event: event["timestamp"]
    )

    time_window = timedelta(seconds=window_seconds)

    for event in sorted_events:

        ip_address = event["ip_address"]
        username = event["username"]
        timestamp = event["timestamp"]
        event_type = event["event_type"]

        key = (ip_address, username)

        # Remove expired brute-force alert tracking.
        if key in active_brute_force:
            last_alert_time = active_brute_force[key]

            if timestamp - last_alert_time > time_window:
                del active_brute_force[key]

        # ----------------------------------------
        # Detect failed login attempts
        # ----------------------------------------

        if event_type == "FAILED_LOGIN":

            attempts = failed_attempts[key]

            attempts.append(timestamp)

            # Remove attempts outside the time window.
            while attempts and timestamp - attempts[0] > time_window:
                attempts.popleft()

            # Generate an alert when the threshold is reached.
            if len(attempts) == threshold:

                alert = {
                    "alert_type": "POSSIBLE_BRUTE_FORCE",
                    "severity": "HIGH",
                    "source_ip": ip_address,
                    "target_account": username,
                    "failed_attempts": len(attempts),
                    "first_attempt": attempts[0],
                    "last_attempt": attempts[-1],
                    "time_window_seconds": window_seconds,
                    "description": (
                        f"{len(attempts)} failed login attempts "
                        f"detected within {window_seconds} seconds."
                    )
                }

                alerts.append(alert)

                # Remember when the brute-force alert occurred.
                active_brute_force[key] = timestamp

        # ----------------------------------------
        # Detect successful login after brute force
        # ----------------------------------------

        elif event_type == "SUCCESS_LOGIN":

            if key in active_brute_force:

                last_alert_time = active_brute_force[key]

                time_difference = (
                    timestamp - last_alert_time
                ).total_seconds()

                if 0 <= time_difference <= window_seconds:

                    alert = {
                        "alert_type": "POSSIBLE_ACCOUNT_COMPROMISE",
                        "severity": "CRITICAL",
                        "source_ip": ip_address,
                        "target_account": username,
                        "failed_attempts": threshold,
                        "first_attempt": last_alert_time,
                        "last_attempt": timestamp,
                        "time_window_seconds": window_seconds,
                        "description": (
                            "A successful login occurred "
                            "shortly after multiple failed "
                            "authentication attempts."
                        )
                    }

                    alerts.append(alert)

                # Clear the active alert so subsequent
                # successful logins don't create duplicates.
                del active_brute_force[key]

            # Reset failed attempts after a successful login.
            failed_attempts.pop(key, None)

    return alerts


def display_security_alerts(alerts):
    """
    Displays security alerts in the terminal.
    """

    print("\n" + "=" * 60)
    print("                 SECURITY ALERTS")
    print("=" * 60)

    if not alerts:
        print("\nNo suspicious authentication patterns detected.")
        return

    print(f"\nTotal Alerts Generated: {len(alerts)}")

    for index, alert in enumerate(alerts, start=1):

        print("\n" + "-" * 60)
        print(f"ALERT #{index}")
        print("-" * 60)

        print(f"Alert Type:      {alert['alert_type']}")
        print(f"Severity:        {alert['severity']}")
        print(f"Source IP:       {alert['source_ip']}")
        print(f"Target Account:  {alert['target_account']}")
        print(f"Failed Attempts: {alert['failed_attempts']}")
        print(f"First Attempt:   {alert['first_attempt']}")
        print(f"Last Attempt:    {alert['last_attempt']}")
        print(f"Time Window:     {alert['time_window_seconds']} seconds")

        print(f"\nDescription: {alert['description']}")

    print("\n" + "=" * 60)

    def test_detects_possible_account_compromise(self):

        start = datetime(2026, 10, 28, 10, 0, 0)

        events = []

        # Five failed login attempts.
        for i in range(5):
            events.append(
                self.create_event(
                    start + timedelta(seconds=i * 2),
                    "192.168.1.10",
                    "admin"
                )
            )

        # Successful login after the failed attempts.
        events.append({
            "timestamp": start + timedelta(seconds=15),
            "event_type": "SUCCESS_LOGIN",
            "ip_address": "192.168.1.10",
            "username": "admin"
        })

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 2)

        self.assertEqual(
            alerts[1]["alert_type"],
            "POSSIBLE_ACCOUNT_COMPROMISE"
        )

        self.assertEqual(
            alerts[1]["severity"],
            "CRITICAL"
        )

    def test_no_compromise_alert_after_time_window(self):

        start = datetime(2026, 10, 28, 10, 0, 0)

        events = []

        for i in range(5):
            events.append(
                self.create_event(
                    start + timedelta(seconds=i * 2),
                    "192.168.1.10",
                    "admin"
                )
            )

        # Successful login occurs too late.
        events.append({
            "timestamp": start + timedelta(minutes=5),
            "event_type": "SUCCESS_LOGIN",
            "ip_address": "192.168.1.10",
            "username": "admin"
        })

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 1)

        self.assertEqual(
            alerts[0]["alert_type"],
            "POSSIBLE_BRUTE_FORCE"
        )