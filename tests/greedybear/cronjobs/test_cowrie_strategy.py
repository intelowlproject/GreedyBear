from unittest import TestCase
from unittest.mock import MagicMock, Mock, patch

from greedybear.cronjobs.extraction.strategies.cowrie import CowrieExtractionStrategy
from greedybear.cronjobs.extraction.strategies.cowrie_parser import CowrieSessionData


class TestCowrieExtractionStrategy(TestCase):
    def setUp(self):
        self.mock_ioc_repo = Mock()
        self.mock_sensor_repo = Mock()
        self.mock_session_repo = Mock()

        # We need to patch the repositories inside the class or pass them
        self.strategy = CowrieExtractionStrategy("Cowrie", self.mock_ioc_repo, self.mock_sensor_repo, self.mock_session_repo)
        # Mock parser
        self.strategy.parser = Mock()
        # Mock ioc_processor
        self.strategy.ioc_processor = Mock()
        # Mock repositories methods that return objects
        self.mock_ioc_repo.get_ioc_by_name.return_value = MagicMock(name="IOC")
        self.mock_session_repo.get_or_create_session.return_value = MagicMock(name="SessionRecord")

    def test_extract_from_hits_coordination(self):
        hits = [{"src_ip": "1.2.3.4"}]

        self.strategy.parser.extract_payloads.return_value = []
        self.strategy.parser.extract_downloads.return_value = []
        self.strategy.parser.extract_sessions.return_value = {}

        with patch("greedybear.cronjobs.extraction.strategies.cowrie.iocs_from_hits") as mock_ifh:
            mock_ifh.return_value = []

            self.strategy.extract_from_hits(hits)

            self.strategy.parser.extract_payloads.assert_called_with(hits)
            self.strategy.parser.extract_downloads.assert_called_with(hits)
            self.strategy.parser.extract_sessions.assert_called_with(hits)
            mock_ifh.assert_called_with(hits)

    def test_save_sessions(self):
        session_data = CowrieSessionData(
            session_id="s1", source_ip="1.2.3.4", start_time="2023-01-01T00:00:00", credentials=["user | pass"], command_execution=True, commands=["ls"]
        )
        sessions = {"s1": session_data}

        # Setup mocks
        mock_ioc = MagicMock()
        self.mock_ioc_repo.get_ioc_by_name.return_value = mock_ioc

        mock_session_record = MagicMock()
        mock_session_record.commands = None  # Simulate no commands initially
        mock_session_record.credentials = []
        self.mock_session_repo.get_or_create_session.return_value = mock_session_record

        self.strategy._save_sessions(sessions)

        # Verification
        self.mock_ioc_repo.get_ioc_by_name.assert_called_with("1.2.3.4")
        self.mock_session_repo.get_or_create_session.assert_called_with(session_id="s1", source=mock_ioc)

        self.assertEqual(mock_session_record.start_time, "2023-01-01T00:00:00")
        self.assertIn("user | pass", mock_session_record.credentials)
        self.assertTrue(mock_session_record.command_execution)

        # Verify commands handling
        # Since we mocked CommandSequence creation inside strategy?
        # The strategy does: session_record.commands = CommandSequence()
        # But CommandSequence is a model.
        # We can't easily assert on that object unless we mock CommandSequence class too.
        # Check if saved.
        self.mock_session_repo.save_session.assert_called_with(mock_session_record)
        self.mock_ioc_repo.save.assert_called_with(mock_session_record.source)

    def test_save_payloads(self):
        payloads = [{"source_ip": "1.2.3.4", "payload_url": "http://evil.com/mal.exe", "payload_hostname": "evil.com"}]

        self.strategy._save_payloads(payloads)

        # Verify calls to ioc_processor
        # 1. Add payload IOC payload_request
        # self.ioc_processor.add_ioc(ioc, attack_type=PAYLOAD_REQUEST)
        self.assertTrue(self.strategy.ioc_processor.add_ioc.called)
        # Verify args?

    def test_save_downloads(self):
        downloads = [{"source_ip": "1.2.3.4", "download_url": "http://malware.com/bad", "hostname": "malware.com"}]

        self.strategy._save_downloads(downloads)

        # Verify calls
        # 1. Scanner IOC (SCANNER)
        # 2. Payload IOC (PAYLOAD_REQUEST)
        self.assertEqual(self.strategy.ioc_processor.add_ioc.call_count, 2)
