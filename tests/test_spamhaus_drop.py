from unittest.mock import MagicMock, patch

from django.test import TestCase
from requests.exceptions import RequestException

from greedybear.cronjobs.spamhaus_drop import SpamhausDropCron


class TestSpamhausDropCron(TestCase):
    @patch("greedybear.cronjobs.spamhaus_drop.requests.get")
    @patch("greedybear.cronjobs.repositories.FireHolRepository")
    def test_fetch_drop_feed_adds_entries(self, mock_repo_class, mock_requests_get):
        """Test normal feed parsing and entries creation."""
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.text = """
        {"cidr":"1.2.3.0/24","sblid":"SBL123","rir":"arin"}
        {"cidr":"4.5.6.0/24","sblid":"SBL456","rir":"arin"}"""
        mock_requests_get.return_value = mock_response

        mock_repo = MagicMock()
        mock_repo.get_or_create.return_value = (None, True)
        mock_repo_class.return_value = mock_repo

        cron = SpamhausDropCron(firehol_repo=mock_repo)
        cron._fetch_drop_feed()

        self.assertEqual(mock_repo.get_or_create.call_count, 2)

    @patch("greedybear.cronjobs.spamhaus_drop.requests.get")
    @patch("greedybear.cronjobs.repositories.FireHolRepository")
    def test_invalid_cidrs_are_skipped(self, mock_repo_class, mock_requests_get):
        """Test that invalid CIDRs are skipped and not added."""
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.text = """
        {"cidr":"invalid_cidr"}
        {"cidr":"123.456.789.0/24"}"""
        mock_requests_get.return_value = mock_response

        mock_repo = MagicMock()
        mock_repo.get_or_create.return_value = (None, True)
        mock_repo_class.return_value = mock_repo

        cron = SpamhausDropCron(firehol_repo=mock_repo)
        cron._fetch_drop_feed()

        # None of the invalid CIDRs should be added
        self.assertEqual(mock_repo.get_or_create.call_count, 0)

    @patch("greedybear.cronjobs.spamhaus_drop.requests.get")
    @patch("greedybear.cronjobs.repositories.FireHolRepository")
    def test_empty_feed_does_nothing(self, mock_repo_class, mock_requests_get):
        """Test that empty feed results in no entries added."""
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.text = ""
        mock_requests_get.return_value = mock_response

        mock_repo = MagicMock()
        mock_repo_class.return_value = mock_repo

        cron = SpamhausDropCron(firehol_repo=mock_repo)
        cron._fetch_drop_feed()

        self.assertEqual(mock_repo.get_or_create.call_count, 0)

    @patch("greedybear.cronjobs.spamhaus_drop.requests.get")
    @patch("greedybear.cronjobs.repositories.FireHolRepository")
    def test_request_exception_is_handled(self, mock_repo_class, mock_requests_get):
        """Test that HTTP errors are logged but do not break the cron."""
        mock_requests_get.side_effect = RequestException("Network error")

        mock_repo = MagicMock()
        mock_repo_class.return_value = mock_repo

        cron = SpamhausDropCron(firehol_repo=mock_repo)
        cron._fetch_drop_feed()

        # get_or_create should never be called due to request failure
        self.assertEqual(mock_repo.get_or_create.call_count, 0)

    @patch("greedybear.cronjobs.repositories.FireHolRepository")
    def test_cleanup_old_entries_calls_repo(self, mock_repo_class):
        """Test that cleanup_old_entries calls repository with correct days."""
        mock_repo = MagicMock()
        mock_repo.cleanup_old_entries.return_value = 5
        mock_repo_class.return_value = mock_repo

        cron = SpamhausDropCron(firehol_repo=mock_repo)
        cron._cleanup_old_entries()

        mock_repo.cleanup_old_entries.assert_called_once_with(days=30)
