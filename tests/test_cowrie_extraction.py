"""
Tests for Cowrie extraction helper functions and strategy.
"""

from unittest.mock import MagicMock, Mock, patch

from greedybear.cronjobs.extraction.strategies.cowrie import (
    CowrieExtractionStrategy,
    normalize_command,
    normalize_credential_field,
    parse_url_hostname,
)
from greedybear.models import CommandSequence, CowrieFileTransfer, CowrieSession
from tests import ExtractionTestCase


class TestHelperFunctions(ExtractionTestCase):
    """Test standalone helper functions."""

    def test_parse_url_hostname_valid_http(self):
        """Test URL parsing with valid HTTP URL."""
        result = parse_url_hostname("http://example.com/path")
        self.assertEqual(result, "example.com")

    def test_parse_url_hostname_valid_https(self):
        """Test URL parsing with valid HTTPS URL."""
        result = parse_url_hostname("https://malware.site/payload.exe")
        self.assertEqual(result, "malware.site")

    def test_parse_url_hostname_with_port(self):
        """Test URL parsing with port number."""
        result = parse_url_hostname("http://evil.com:8080/download")
        self.assertEqual(result, "evil.com")

    def test_parse_url_hostname_invalid_url(self):
        """Test URL parsing with invalid URL."""
        result = parse_url_hostname("not_a_url")
        self.assertIsNone(result)

    def test_parse_url_hostname_empty_string(self):
        """Test URL parsing with empty string."""
        result = parse_url_hostname("")
        self.assertIsNone(result)

    def test_normalize_command_with_prefix(self):
        """Test command normalization with CMD prefix."""
        result = normalize_command("CMD: ls -la")
        self.assertEqual(result, "ls -la")

    def test_normalize_command_without_prefix(self):
        """Test command normalization without prefix."""
        result = normalize_command("pwd")
        self.assertEqual(result, "pwd")

    def test_normalize_command_with_null_chars(self):
        """Test command normalization with null characters."""
        result = normalize_command("CMD: echo\x00test")
        self.assertEqual(result, "echo[NUL]test")

    def test_normalize_command_truncation(self):
        """Test command truncation to 1024 characters."""
        long_command = "CMD: " + "A" * 2000
        result = normalize_command(long_command)
        self.assertEqual(len(result), 1024)
        self.assertTrue(result.startswith("A"))

    def test_normalize_credential_field_with_null(self):
        """Test credential normalization with null characters."""
        result = normalize_credential_field("user\x00name")
        self.assertEqual(result, "user[NUL]name")

    def test_normalize_credential_field_clean(self):
        """Test credential normalization with clean string."""
        result = normalize_credential_field("admin")
        self.assertEqual(result, "admin")


class TestCowrieExtractionStrategy(ExtractionTestCase):
    """Test CowrieExtractionStrategy class."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_ioc_repo = Mock()
        self.mock_sensor_repo = Mock()
        self.mock_session_repo = Mock()

        self.strategy = CowrieExtractionStrategy(
            "Cowrie",
            self.mock_ioc_repo,
            self.mock_sensor_repo,
            self.mock_session_repo,
        )
        self.strategy.ioc_processor = Mock()

    def test_extract_payload_in_messages_with_url(self):
        """Test extraction of URLs from login failure messages."""
        hits = [
            {
                "src_ip": "1.2.3.4",
                "eventid": "cowrie.login.failed",
                "message": "Failed login with http://evil.com/malware.exe",
            }
        ]

        scanner_mock = Mock()
        scanner_mock.related_ioc.all.return_value = []
        payload_mock = Mock()
        payload_mock.related_ioc.all.return_value = []

        self.mock_ioc_repo.get_ioc_by_name.side_effect = [scanner_mock, payload_mock]

        self.strategy._extract_possible_payload_in_messages(hits)

        # Should have called add_ioc for the payload
        self.assertEqual(self.strategy.ioc_processor.add_ioc.call_count, 1)
        call_args = self.strategy.ioc_processor.add_ioc.call_args
        ioc_arg = call_args[0][0]

        self.assertEqual(ioc_arg.name, "evil.com")
        self.assertIn("http://evil.com/malware.exe", ioc_arg.related_urls)
        # Verify honeypot is set via general_honeypot_name argument
        self.assertEqual(call_args.kwargs.get("general_honeypot_name"), "Cowrie")

    def test_extract_payload_in_messages_no_url(self):
        """Test extraction when message has no URL."""
        hits = [
            {
                "src_ip": "1.2.3.4",
                "eventid": "cowrie.login.failed",
                "message": "Failed login attempt",
            }
        ]

        self.strategy._extract_possible_payload_in_messages(hits)

        # Should not add any IOC
        self.strategy.ioc_processor.add_ioc.assert_not_called()

    def test_extract_payload_different_ips(self):
        """Test that payloads from different IPs are all processed."""
        hits = [
            {
                "src_ip": "5.6.7.8",
                "eventid": "cowrie.login.failed",
                "message": "http://evil.com/malware",
            }
        ]

        scanner_mock = Mock()
        payload_mock = Mock()
        self.mock_ioc_repo.get_ioc_by_name.side_effect = [scanner_mock, payload_mock]

        self.strategy._extract_possible_payload_in_messages(hits)

        # Should process the payload from any IP
        self.strategy.ioc_processor.add_ioc.assert_called_once()

    def test_extract_payload_in_messages_empty_hits(self):
        """Test extraction with empty hits list."""
        hits = []

        self.strategy._extract_possible_payload_in_messages(hits)

        # Should not call add_ioc when there are no hits
        self.strategy.ioc_processor.add_ioc.assert_not_called()

    def test_get_url_downloads(self):
        """Test extraction of file download attempts."""
        hits = [
            {
                "src_ip": "1.2.3.4",
                "eventid": "cowrie.session.file_download",
                "url": "http://malware.com/bad.exe",
            }
        ]

        scanner_mock = Mock()
        payload_mock = Mock()

        self.mock_ioc_repo.get_ioc_by_name.side_effect = [scanner_mock, payload_mock]
        mock_payload_record = Mock()
        self.strategy.ioc_processor.add_ioc.return_value = mock_payload_record

        self.strategy._get_url_downloads(hits)

        # Should only create 1 IOC: payload hostname (scanner already added in _get_scanners)
        self.assertEqual(self.strategy.ioc_processor.add_ioc.call_count, 1)
        self.assertEqual(self.strategy.added_url_downloads, 1)

    def test_get_url_downloads_invalid_url(self):
        """Test download extraction with invalid URL."""
        hits = [
            {
                "src_ip": "1.2.3.4",
                "eventid": "cowrie.session.file_download",
                "url": "not_a_valid_url",
            }
        ]

        self.strategy.ioc_processor.add_ioc.return_value = Mock()

        self.strategy._get_url_downloads(hits)

        # Should not create any IOC (invalid URL, and scanner already added in _get_scanners)
        self.strategy.ioc_processor.add_ioc.assert_not_called()

    def test_process_session_hit_connect(self):
        """Test processing of session connect event."""
        session_record = Mock()
        session_record.interaction_count = 0
        hit = {
            "eventid": "cowrie.session.connect",
            "timestamp": "2023-01-01T10:00:00",
        }
        ioc = Mock(name="1.2.3.4")

        self.strategy._process_session_hit(session_record, hit, ioc)

        self.assertEqual(session_record.start_time, "2023-01-01T10:00:00")
        self.assertEqual(session_record.interaction_count, 1)

    def test_process_session_hit_login_failed(self):
        """Test processing of login failure event."""
        session_record = Mock()
        session_record.credentials = []
        session_record.source = Mock(login_attempts=0)
        session_record.interaction_count = 0

        hit = {
            "eventid": "cowrie.login.failed",
            "timestamp": "2023-01-01T10:00:01",
            "username": "root",
            "password": "password123",
        }
        ioc = Mock(name="1.2.3.4")

        self.strategy._process_session_hit(session_record, hit, ioc)

        self.assertTrue(session_record.login_attempt)
        self.assertIn("root | password123", session_record.credentials)
        self.assertEqual(session_record.source.login_attempts, 1)

    def test_process_session_hit_command_input(self):
        """Test processing of command input event."""
        session_record = Mock()
        session_record.commands = None
        session_record.interaction_count = 0

        hit = {
            "eventid": "cowrie.command.input",
            "timestamp": "2023-01-01T10:00:05",
            "message": "CMD: ls -la",
        }
        ioc = Mock(name="1.2.3.4")

        self.strategy._process_session_hit(session_record, hit, ioc)

        self.assertTrue(session_record.command_execution)
        self.assertIsInstance(session_record.commands, CommandSequence)
        self.assertEqual(session_record.commands.first_seen, "2023-01-01T10:00:05")
        self.assertIn("ls -la", session_record.commands.commands)

    def test_process_session_hit_session_closed(self):
        """Test processing of session closed event."""
        session_record = Mock()
        session_record.interaction_count = 0
        hit = {
            "eventid": "cowrie.session.closed",
            "timestamp": "2023-01-01T10:00:10",
            "duration": 10.5,
        }
        ioc = Mock(name="1.2.3.4")

        self.strategy._process_session_hit(session_record, hit, ioc)

        self.assertEqual(session_record.duration, 10.5)

    def test_add_fks_both_exist(self):
        """Test linking IOCs when both exist."""
        scanner_mock = MagicMock()
        hostname_mock = MagicMock()

        self.mock_ioc_repo.get_ioc_by_name.side_effect = [scanner_mock, hostname_mock]

        self.strategy._add_fks("1.2.3.4", "evil.com")

        scanner_mock.related_ioc.add.assert_called_once_with(hostname_mock)
        hostname_mock.related_ioc.add.assert_called_once_with(scanner_mock)
        self.assertEqual(self.mock_ioc_repo.save.call_count, 2)

    def test_add_fks_scanner_none(self):
        """Test linking when scanner IOC doesn't exist."""
        hostname_mock = MagicMock()

        self.mock_ioc_repo.get_ioc_by_name.side_effect = [None, hostname_mock]

        self.strategy._add_fks("1.2.3.4", "evil.com")

        # Should not save anything (early return when either is None)
        self.mock_ioc_repo.save.assert_not_called()

    def test_deduplicate_command_sequence_new(self):
        """Test command sequence deduplication for new sequence."""
        session = Mock()
        session.commands = Mock()
        session.commands.commands = ["ls", "pwd", "whoami"]

        self.mock_session_repo.get_command_sequence_by_hash.return_value = None

        result = self.strategy._deduplicate_command_sequence(session)

        self.assertFalse(result)
        self.assertIsNotNone(session.commands.commands_hash)

    def test_deduplicate_command_sequence_existing(self):
        """Test command sequence deduplication for existing sequence."""
        session = Mock()
        session.commands = Mock()
        session.commands.commands = ["ls", "pwd", "whoami"]
        session.commands.last_seen = "2023-01-01T10:00:10"

        existing_cmd_seq = Mock()
        self.mock_session_repo.get_command_sequence_by_hash.return_value = existing_cmd_seq

        result = self.strategy._deduplicate_command_sequence(session)

        self.assertTrue(result)
        self.assertEqual(session.commands, existing_cmd_seq)
        self.assertEqual(session.commands.last_seen, "2023-01-01T10:00:10")

    def test_process_session_hit_file_download_with_shasum(self):
        """Test that file_download events with shasum create a file transfer record."""
        session_record = CowrieSession(session_id=0x123456, source=self.ioc)
        hit = {
            "eventid": "cowrie.session.file_download",
            "timestamp": "2023-01-01T10:00:05",
            "url": "http://malware.com/bad.exe",
            "shasum": "a" * 64,
            "destfile": "/tmp/bad.exe",
        }
        ioc = Mock(name="1.2.3.4")

        self.strategy._process_session_hit(session_record, hit, ioc)

        self.assertIsNotNone(session_record.file_transfers)
        self.assertIsInstance(session_record.file_transfers, CowrieFileTransfer)
        self.assertEqual(len(session_record.file_transfers.transfers), 1)
        transfer = session_record.file_transfers.transfers[0]
        self.assertEqual(transfer["shasum"], "a" * 64)
        self.assertEqual(transfer["url"], "http://malware.com/bad.exe")
        self.assertEqual(transfer["dst_filename"], "/tmp/bad.exe")
        self.assertEqual(session_record.interaction_count, 1)

    def test_process_session_hit_file_download_without_shasum(self):
        """Test that file_download events without shasum are skipped gracefully."""
        session_record = CowrieSession(session_id=0x789012, source=self.ioc)
        hit = {
            "eventid": "cowrie.session.file_download",
            "timestamp": "2023-01-01T10:00:05",
            "url": "http://malware.com/bad.exe",
        }
        ioc = Mock(name="1.2.3.4")

        self.strategy._process_session_hit(session_record, hit, ioc)

        self.assertIsNone(session_record.file_transfers)
        self.assertEqual(session_record.interaction_count, 1)

    def test_process_session_hit_file_upload_with_shasum(self):
        """Test that file_upload events with shasum create a file transfer record."""
        session_record = CowrieSession(session_id=0x345678, source=self.ioc)
        hit = {
            "eventid": "cowrie.session.file_upload",
            "timestamp": "2023-01-01T10:00:07",
            "shasum": "c" * 64,
            "destfile": "/tmp/upload.sh",
        }
        ioc = Mock(name="1.2.3.4")

        self.strategy._process_session_hit(session_record, hit, ioc)

        self.assertIsNotNone(session_record.file_transfers)
        self.assertEqual(len(session_record.file_transfers.transfers), 1)
        transfer = session_record.file_transfers.transfers[0]
        self.assertEqual(transfer["shasum"], "c" * 64)
        self.assertEqual(transfer["dst_filename"], "/tmp/upload.sh")
        self.assertEqual(session_record.interaction_count, 1)

    def test_get_sessions_saves_file_transfers(self):
        """Test that _get_sessions saves file_transfers like command sequences."""
        ioc = Mock()
        ioc.name = "1.2.3.4"

        mock_file_transfer = Mock(spec=CowrieFileTransfer)
        mock_file_transfer.transfers = [{"shasum": "a" * 64}]
        mock_session = Mock()
        mock_session.commands = None
        mock_session.file_transfers = mock_file_transfer

        self.mock_session_repo.get_or_create_session.return_value = mock_session

        hits = [
            {
                "src_ip": "1.2.3.4",
                "session": "abc123",
                "eventid": "cowrie.session.connect",
                "timestamp": "2023-01-01T10:00:00",
            }
        ]

        with patch.object(self.strategy, "_process_session_hit"):
            self.strategy._get_sessions(ioc, hits)

        self.mock_session_repo.save_file_transfer.assert_called_once_with(mock_file_transfer)
        self.mock_session_repo.save_session.assert_called_once_with(mock_session)

    @patch("greedybear.cronjobs.extraction.strategies.cowrie.iocs_from_hits")
    def test_extract_from_hits_integration(self, mock_iocs_from_hits):
        """Test the main extract_from_hits coordination."""
        mock_ioc = Mock(name="1.2.3.4")
        # Return list of IOCs as expected by the new format
        mock_iocs_from_hits.return_value = [mock_ioc]

        mock_ioc_record = Mock()
        self.strategy.ioc_processor.add_ioc.return_value = mock_ioc_record

        hits = [{"src_ip": "1.2.3.4", "session": "s1", "eventid": "cowrie.session.connect"}]

        with patch.object(self.strategy, "_get_sessions"):
            with patch.object(self.strategy, "_extract_possible_payload_in_messages"):
                self.strategy.extract_from_hits(hits)

        # Verify scanner was processed with Cowrie as honeypot
        self.strategy.ioc_processor.add_ioc.assert_called()
        call_args = self.strategy.ioc_processor.add_ioc.call_args
        self.assertEqual(call_args.kwargs.get("general_honeypot_name"), "Cowrie")
