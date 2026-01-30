import unittest
from unittest.mock import MagicMock, patch

import requests

from greedybear.cronjobs.abuseipdb_feed import AbuseIPDBCron


class AbuseIPDBCronTest(unittest.TestCase):
    def setUp(self):
        self.mock_abuseipdb_repo = MagicMock()
        self.mock_ioc_repo = MagicMock()
        self.cron = AbuseIPDBCron(abuseipdb_repo=self.mock_abuseipdb_repo, ioc_repo=self.mock_ioc_repo)

    @patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "test_key"})
    @patch("greedybear.cronjobs.abuseipdb_feed.requests.get")
    def test_successful_download_and_parse(self, mock_get):
        # Mock JSON response
        json_data = {
            "data": [
                {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 100, "lastReportedAt": "2024-01-30T10:00:00+00:00"},
                {"ipAddress": "5.6.7.8", "abuseConfidenceScore": 95, "lastReportedAt": "2024-01-29T15:30:00+00:00"},
            ]
        }

        mock_response = MagicMock()
        mock_response.json.return_value = json_data
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        self.mock_abuseipdb_repo.get_or_create.side_effect = [
            (MagicMock(), True),  # First IP created
            (MagicMock(), True),  # Second IP created
        ]

        self.cron.run()

        # Verify deletion of old entries
        self.mock_abuseipdb_repo.delete_all.assert_called_once()

        # Verify two entries were processed
        self.assertEqual(self.mock_abuseipdb_repo.get_or_create.call_count, 2)

        # Verify API was called with correct parameters
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        self.assertEqual(call_args.kwargs["params"]["confidenceMinimum"], 75)
        self.assertEqual(call_args.kwargs["params"]["limit"], 10000)

        # Verify IOC reputation was updated
        self.assertEqual(self.mock_ioc_repo.update_ioc_reputation.call_count, 2)

    @patch.dict("os.environ", {}, clear=True)
    def test_missing_api_key_returns_early(self):
        self.cron.run()

        # Should not make any API calls or create entries
        self.mock_abuseipdb_repo.get_or_create.assert_not_called()

    @patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "test_key"})
    @patch("greedybear.cronjobs.abuseipdb_feed.requests.get")
    def test_max_entries_limit(self, mock_get):
        # Create response with many entries
        data_entries = []
        for i in range(15000):  # More than MAX_ENTRIES (10000)
            data_entries.append(
                {"ipAddress": f"1.{i // 65536}.{(i // 256) % 256}.{i % 256}", "abuseConfidenceScore": 100, "lastReportedAt": "2024-01-30T10:00:00+00:00"}
            )

        mock_response = MagicMock()
        mock_response.json.return_value = {"data": data_entries}
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        self.mock_abuseipdb_repo.get_or_create.return_value = (MagicMock(), True)

        self.cron.run()

        # Should only process MAX_ENTRIES (10000)
        self.assertEqual(self.mock_abuseipdb_repo.get_or_create.call_count, self.cron.MAX_ENTRIES)

    @patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "test_key"})
    @patch("greedybear.cronjobs.abuseipdb_feed.requests.get")
    def test_filters_invalid_ips(self, mock_get):
        json_data = {
            "data": [
                {"ipAddress": "invalid.ip.address", "abuseConfidenceScore": 100, "lastReportedAt": "2024-01-30T10:00:00+00:00"},
                {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 95, "lastReportedAt": "2024-01-29T15:30:00+00:00"},
            ]
        }

        mock_response = MagicMock()
        mock_response.json.return_value = json_data
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        self.mock_abuseipdb_repo.get_or_create.return_value = (MagicMock(), True)

        self.cron.run()

        # Only one valid IP should be processed
        self.assertEqual(self.mock_abuseipdb_repo.get_or_create.call_count, 1)

    @patch.dict("os.environ", {"ABUSEIPDB_API_KEY": "test_key"})
    @patch("greedybear.cronjobs.abuseipdb_feed.requests.get")
    def test_request_failure_raises_exception(self, mock_get):
        mock_get.side_effect = requests.RequestException("API error")

        with self.assertRaises(requests.RequestException):
            self.cron.run()


if __name__ == "__main__":
    unittest.main()
