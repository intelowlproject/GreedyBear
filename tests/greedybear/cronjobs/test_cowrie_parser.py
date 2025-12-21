from unittest import TestCase, main
from unittest.mock import Mock

from greedybear.cronjobs.extraction.strategies.cowrie_parser import CowrieLogParser


class TestCowrieLogParser(TestCase):
    def setUp(self):
        self.mock_log = Mock()
        self.parser = CowrieLogParser(self.mock_log)

    def test_extract_payloads(self):
        hits = [
            {"eventid": "cowrie.login.failed", "message": "some message http://evil.com/payload.exe", "src_ip": "1.2.3.4"},
            {"eventid": "cowrie.session.file_upload", "message": "uploading https://phishing.site/", "src_ip": "5.6.7.8"},
            {"eventid": "other.event", "message": "http://ignore.k", "src_ip": "10.0.0.1"},
            {"eventid": "cowrie.login.failed", "message": "no url here", "src_ip": "1.2.3.4"},
        ]

        results = self.parser.extract_payloads(hits)

        self.assertEqual(len(results), 2)

        self.assertEqual(results[0]["source_ip"], "1.2.3.4")
        self.assertEqual(results[0]["payload_url"], "http://evil.com/payload.exe")
        self.assertEqual(results[0]["payload_hostname"], "evil.com")

        self.assertEqual(results[1]["source_ip"], "5.6.7.8")
        self.assertEqual(results[1]["payload_url"], "https://phishing.site")
        self.assertEqual(results[1]["payload_hostname"], "phishing.site")

    def test_extract_downloads(self):
        hits = [
            {"eventid": "cowrie.session.file_download", "url": "http://malware.com/bad", "src_ip": "1.2.3.4"},
            {"eventid": "cowrie.session.file_download", "url": "not_a_url", "src_ip": "5.6.7.8"},
            {"eventid": "other.event", "url": "http://ignore.k", "src_ip": "10.0.0.1"},
        ]

        results = self.parser.extract_downloads(hits)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["source_ip"], "1.2.3.4")
        self.assertEqual(results[0]["download_url"], "http://malware.com/bad")
        self.assertEqual(results[0]["hostname"], "malware.com")

    def test_extract_sessions(self):
        hits = [
            {"session": "s1", "eventid": "cowrie.session.connect", "timestamp": "2023-01-01T10:00:00", "src_ip": "1.1.1.1"},
            {"session": "s1", "eventid": "cowrie.login.failed", "timestamp": "2023-01-01T10:00:01", "username": "root", "password": "123", "src_ip": "1.1.1.1"},
            {"session": "s1", "eventid": "cowrie.command.input", "timestamp": "2023-01-01T10:00:05", "message": "CMD: ls -la", "src_ip": "1.1.1.1"},
            {"session": "s1", "eventid": "cowrie.session.closed", "timestamp": "2023-01-01T10:00:10", "duration": 10.0, "src_ip": "1.1.1.1"},
            {"session": "s2", "eventid": "cowrie.session.connect", "timestamp": "2023-01-01T10:05:00", "src_ip": "2.2.2.2"},
            {"eventid": "random", "timestamp": "2023-01-01T10:00:00"},
        ]

        sessions = self.parser.extract_sessions(hits)

        self.assertEqual(len(sessions), 2)

        s1 = sessions["s1"]
        self.assertEqual(s1.source_ip, "1.1.1.1")
        self.assertEqual(s1.start_time, "2023-01-01T10:00:00")
        self.assertEqual(s1.duration, 10.0)
        self.assertTrue(s1.login_attempt)
        self.assertEqual(s1.credentials, ["root | 123"])
        self.assertTrue(s1.command_execution)
        self.assertEqual(s1.commands, ["ls -la"])
        self.assertEqual(s1.commands_first_seen, "2023-01-01T10:00:05")
        self.assertEqual(s1.interaction_count, 4)

        s2 = sessions["s2"]
        self.assertEqual(s2.source_ip, "2.2.2.2")
        self.assertFalse(s2.login_attempt)
