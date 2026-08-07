import importlib.util
import pathlib
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("smtp-event-forwarder.py")
SPEC = importlib.util.spec_from_file_location("smtp_event_forwarder", MODULE_PATH)
FORWARDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FORWARDER)


class ParseTerminalOutcomeTests(unittest.TestCase):
    def test_parses_successful_downstream_delivery(self):
        event = FORWARDER.parse_line(
            "Jul 30 12:00:00 mx postfix/smtp[123]: ABC123: "
            "to=<user@example.net>, relay=mail.example.net[192.0.2.10]:25, "
            "delay=1, dsn=2.0.0, status=sent (250 2.0.0 queued)"
        )

        self.assertEqual(event["queue_id"], "ABC123")
        self.assertEqual(event["event_type"], "delivered")
        self.assertEqual(event["phase"], "delivery")
        self.assertEqual(event["to_addr"], "user@example.net")
        self.assertEqual(event["relay"], "mail.example.net[192.0.2.10]:25")
        self.assertEqual(event["dsn"], "2.0.0")

    def test_parses_milter_discard(self):
        event = FORWARDER.parse_line(
            "Jul 30 12:00:00 mx postfix/cleanup[321]: DEF456: "
            "milter-discard: END-OF-MESSAGE from unknown[192.0.2.20]: "
            "message discarded; from=<bad@example.org> to=<user@example.net> "
            "proto=ESMTP helo=<example.org>"
        )

        self.assertEqual(event["queue_id"], "DEF456")
        self.assertEqual(event["event_type"], "discarded")
        self.assertEqual(event["phase"], "end_of_message")
        self.assertEqual(event["from_addr"], "bad@example.org")
        self.assertEqual(event["to_addr"], "user@example.net")
        self.assertEqual(event["client_ip"], "192.0.2.20")

    def test_ignores_non_terminal_queue_line(self):
        event = FORWARDER.parse_line(
            "Jul 30 12:00:00 mx postfix/qmgr[111]: ABC123: "
            "from=<sender@example.org>, size=1234, nrcpt=1 (queue active)"
        )

        self.assertIsNone(event)


if __name__ == "__main__":
    unittest.main()
