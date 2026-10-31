import unittest
from datetime import datetime

from app.parser import parse_log_line


class TestLogParser(unittest.TestCase):

    def test_valid_failed_login(self):
        """Test parsing a valid failed login event."""

        line = (
            "2026-10-28 10:00:01 "
            "FAILED_LOGIN user=admin ip=192.168.1.10"
        )

        event = parse_log_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event["event_type"], "FAILED_LOGIN")
        self.assertEqual(event["username"], "admin")
        self.assertEqual(event["ip_address"], "192.168.1.10")
        self.assertEqual(
            event["timestamp"],
            datetime(2026, 10, 28, 10, 0, 1)
        )

    def test_valid_successful_login(self):
        """Test parsing a valid successful login event."""

        line = (
            "2026-10-28 10:01:00 "
            "SUCCESS_LOGIN user=john ip=192.168.1.20"
        )

        event = parse_log_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event["event_type"], "SUCCESS_LOGIN")
        self.assertEqual(event["username"], "john")
        self.assertEqual(event["ip_address"], "192.168.1.20")

    def test_invalid_ip_address(self):
        """Test that invalid IP addresses are rejected."""

        line = (
            "2026-10-28 10:00:01 "
            "FAILED_LOGIN user=admin ip=999.999.999.999"
        )

        event = parse_log_line(line)

        self.assertIsNone(event)

    def test_invalid_event_type(self):
        """Test that unknown event types are rejected."""

        line = (
            "2026-10-28 10:00:01 "
            "UNKNOWN_EVENT user=admin ip=192.168.1.10"
        )

        event = parse_log_line(line)

        self.assertIsNone(event)

    def test_invalid_timestamp(self):
        """Test that invalid timestamps are rejected."""

        line = (
            "2026-99-99 10:00:01 "
            "FAILED_LOGIN user=admin ip=192.168.1.10"
        )

        event = parse_log_line(line)

        self.assertIsNone(event)

    def test_missing_username(self):
        """Test that missing usernames are rejected."""

        line = (
            "2026-10-28 10:00:01 "
            "FAILED_LOGIN user= ip=192.168.1.10"
        )

        event = parse_log_line(line)

        self.assertIsNone(event)

    def test_missing_ip_address(self):
        """Test that missing IP addresses are rejected."""

        line = (
            "2026-10-28 10:00:01 "
            "FAILED_LOGIN user=admin ip="
        )

        event = parse_log_line(line)

        self.assertIsNone(event)

    def test_incomplete_log_entry(self):
        """Test that incomplete log entries are rejected."""

        line = "2026-10-28 FAILED_LOGIN user=admin"

        event = parse_log_line(line)

        self.assertIsNone(event)

    def test_empty_log_entry(self):
        """Test that empty log entries are rejected."""

        line = ""

        event = parse_log_line(line)

        self.assertIsNone(event)


if __name__ == "__main__":
    unittest.main()