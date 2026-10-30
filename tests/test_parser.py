import unittest

from app.parser import parse_log_line


class TestLogParser(unittest.TestCase):

    def test_valid_failed_login(self):

        line = (
            "2026-10-28 10:00:01 "
            "FAILED_LOGIN user=admin ip=192.168.1.10"
        )

        event = parse_log_line(line)

        self.assertIsNotNone(event)

        self.assertEqual(
            event["event_type"],
            "FAILED_LOGIN"
        )

        self.assertEqual(
            event["username"],
            "admin"
        )

        self.assertEqual(
            event["ip_address"],
            "192.168.1.10"
        )

    def test_invalid_ip_address(self):

        line = (
            "2026-10-28 10:00:01 "
            "FAILED_LOGIN user=admin ip=999.999.999.999"
        )

        event = parse_log_line(line)

        self.assertIsNone(event)

    def test_invalid_event_type(self):

        line = (
            "2026-10-28 10:00:01 "
            "UNKNOWN_EVENT user=admin ip=192.168.1.10"
        )

        event = parse_log_line(line)

        self.assertIsNone(event)

    def test_invalid_timestamp(self):

        line = (
            "2026-99-99 10:00:01 "
            "FAILED_LOGIN user=admin ip=192.168.1.10"
        )

        event = parse_log_line(line)

        self.assertIsNone(event)


if __name__ == "__main__":
    unittest.main()