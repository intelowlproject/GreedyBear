import unittest
from unittest.mock import MagicMock, patch

import requests

from greedybear.cronjobs.threatfox_feed import ThreatFoxCron


class ThreatFoxCronTest(unittest.TestCase):
    def setUp(self):
        self.mock_threatfox_repo = MagicMock()
        self.mock_ioc_repo = MagicMock()
        self.cron = ThreatFoxCron(threatfox_repo=self.mock_threatfox_repo, ioc_repo=self.mock_ioc_repo)

    @patch("greedybear.cronjobs.threatfox_feed.requests.get")
    def test_successful_download_and_parse(self, mock_get):
        # Mock CSV response
        csv_data = """# ThreatFox CSV
ioc,malware,last_online
1.2.3.4:80,Emotet,2024-01-30T10:00:00Z
5.6.7.8:443,Dridex,2024-01-29T15:30:00Z"""

        mock_response = MagicMock()
        mock_response.text = csv_data
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        self.mock_threatfox_repo.get_or_create.side_effect = [
            (MagicMock(), True),  # First IP created
            (MagicMock(), True),  # Second IP created
        ]

        self.cron.run()

        # Verify deletion of old entries
        self.mock_threatfox_repo.delete_all.assert_called_once()

        # Verify two entries were processed
        self.assertEqual(self.mock_threatfox_repo.get_or_create.call_count, 2)

        # Verify IOC reputation was updated
        self.assertEqual(self.mock_ioc_repo.update_ioc_reputation.call_count, 2)

    @patch("greedybear.cronjobs.threatfox_feed.requests.get")
    def test_max_entries_limit(self, mock_get):
        # Create CSV with many entries
        csv_lines = ["ioc,malware,last_online"]
        for i in range(15000):  # More than MAX_ENTRIES (10000)
            csv_lines.append(f"1.2.{i // 256}.{i % 256}:80,Emotet,2024-01-30T10:00:00Z")

        mock_response = MagicMock()
        mock_response.text = "\n".join(csv_lines)
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        self.mock_threatfox_repo.get_or_create.return_value = (MagicMock(), True)

        self.cron.run()

        # Should only process MAX_ENTRIES (10000)
        self.assertEqual(self.mock_threatfox_repo.get_or_create.call_count, self.cron.MAX_ENTRIES)

    @patch("greedybear.cronjobs.threatfox_feed.requests.get")
    def test_filters_invalid_ips(self, mock_get):
        csv_data = """ioc,malware,last_online
invalid.ip:80,Emotet,2024-01-30T10:00:00Z
1.2.3.4:443,Dridex,2024-01-29T15:30:00Z"""

        mock_response = MagicMock()
        mock_response.text = csv_data
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        self.mock_threatfox_repo.get_or_create.return_value = (MagicMock(), True)

        self.cron.run()

        # Only one valid IP should be processed
        self.assertEqual(self.mock_threatfox_repo.get_or_create.call_count, 1)

    @patch("greedybear.cronjobs.threatfox_feed.requests.get")
    def test_request_failure_raises_exception(self, mock_get):
        mock_get.side_effect = requests.RequestException("Connection failed")

        with self.assertRaises(requests.RequestException):
            self.cron.run()


if __name__ == "__main__":
    unittest.main()
