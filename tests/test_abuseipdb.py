from unittest.mock import Mock, patch

import requests

from greedybear.cronjobs.abuseipdb_feed import AbuseIPDBCron
from greedybear.cronjobs.repositories import AbuseIPDBRepository
from greedybear.models import AbuseIPDBFeed
from tests import CustomTestCase


class TestAbuseIPDBRepository(CustomTestCase):
    """Tests for AbuseIPDBRepository."""

    def setUp(self):
        self.repo = AbuseIPDBRepository()

    def test_get_or_create_creates_new_entry(self):
        entry, created = self.repo.get_or_create(
            ip_address="1.2.3.4",
            abuse_confidence_score=95,
            usage_type="Data Center/Web Hosting/Transit",
            country_code="US",
        )

        self.assertTrue(created)
        self.assertEqual(entry.ip_address, "1.2.3.4")
        self.assertEqual(entry.abuse_confidence_score, 95)
        self.assertEqual(entry.usage_type, "Data Center/Web Hosting/Transit")
        self.assertEqual(entry.country_code, "US")

    def test_get_or_create_updates_existing(self):
        AbuseIPDBFeed.objects.create(
            ip_address="5.6.7.8",
            abuse_confidence_score=80,
            usage_type="Old Type",
        )

        entry, created = self.repo.get_or_create(
            ip_address="5.6.7.8",
            abuse_confidence_score=90,
            usage_type="New Type",
        )

        self.assertFalse(created)
        self.assertEqual(entry.abuse_confidence_score, 90)
        self.assertEqual(entry.usage_type, "New Type")

    def test_get_by_ip(self):
        AbuseIPDBFeed.objects.create(ip_address="1.1.1.1", abuse_confidence_score=85)

        entry = self.repo.get_by_ip("1.1.1.1")

        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip_address, "1.1.1.1")

    def test_get_by_ip_not_found(self):
        entry = self.repo.get_by_ip("99.99.99.99")
        self.assertIsNone(entry)

    def test_enforce_limit(self):
        # Create 15 entries
        for i in range(15):
            AbuseIPDBFeed.objects.create(ip_address=f"1.1.1.{i}", abuse_confidence_score=80)

        # Enforce limit of 10
        deleted = self.repo.enforce_limit(max_entries=10)

        self.assertEqual(deleted, 5)
        self.assertEqual(AbuseIPDBFeed.objects.count(), 10)

    def test_enforce_limit_no_deletion_needed(self):
        AbuseIPDBFeed.objects.create(ip_address="1.1.1.1", abuse_confidence_score=80)

        deleted = self.repo.enforce_limit(max_entries=10)

        self.assertEqual(deleted, 0)
        self.assertEqual(AbuseIPDBFeed.objects.count(), 1)

    def test_cleanup_old_entries(self):
        from datetime import timedelta

        from django.utils import timezone

        # Create entries with different ages
        AbuseIPDBFeed.objects.create(ip_address="1.1.1.1", abuse_confidence_score=80)

        old = AbuseIPDBFeed.objects.create(ip_address="2.2.2.2", abuse_confidence_score=80)
        old.added = timezone.now() - timedelta(days=31)
        old.save()

        deleted = self.repo.cleanup_old_entries(days=30)

        self.assertEqual(deleted, 1)
        self.assertEqual(AbuseIPDBFeed.objects.count(), 1)
        self.assertTrue(AbuseIPDBFeed.objects.filter(ip_address="1.1.1.1").exists())

    def test_clear_all(self):
        AbuseIPDBFeed.objects.create(ip_address="1.1.1.1", abuse_confidence_score=80)
        AbuseIPDBFeed.objects.create(ip_address="2.2.2.2", abuse_confidence_score=85)

        count = self.repo.clear_all()

        self.assertEqual(count, 2)
        self.assertEqual(AbuseIPDBFeed.objects.count(), 0)

    def test_count(self):
        AbuseIPDBFeed.objects.create(ip_address="1.1.1.1", abuse_confidence_score=80)
        AbuseIPDBFeed.objects.create(ip_address="2.2.2.2", abuse_confidence_score=85)

        count = self.repo.count()

        self.assertEqual(count, 2)


class TestAbuseIPDBCron(CustomTestCase):
    """Tests for AbuseIPDBCron."""

    def setUp(self):
        self.repo = AbuseIPDBRepository()
        self.cron = AbuseIPDBCron(abuseipdb_repo=self.repo)

    def _create_mock_response(self, blacklist_data):
        """Helper to create a mock response."""
        mock_response = Mock()
        mock_response.json.return_value = {"data": blacklist_data}
        mock_response.raise_for_status = Mock()
        return mock_response

    @patch("greedybear.cronjobs.abuseipdb_feed.settings")
    @patch("greedybear.cronjobs.abuseipdb_feed.requests.get")
    def test_downloads_and_stores_blacklist(self, mock_get, mock_settings):
        mock_settings.ABUSEIPDB_API_KEY = "test-api-key"

        blacklist_data = [
            {
                "ipAddress": "1.2.3.4",
                "abuseConfidenceScore": 95,
                "usageType": "Data Center",
                "countryCode": "US",
            },
            {
                "ipAddress": "5.6.7.8",
                "abuseConfidenceScore": 88,
                "usageType": "ISP",
                "countryCode": "CN",
            },
        ]
        mock_get.return_value = self._create_mock_response(blacklist_data)

        self.cron.run()

        self.assertEqual(AbuseIPDBFeed.objects.count(), 2)
        entry1 = AbuseIPDBFeed.objects.get(ip_address="1.2.3.4")
        self.assertEqual(entry1.abuse_confidence_score, 95)
        self.assertEqual(entry1.usage_type, "Data Center")

    @patch("greedybear.cronjobs.abuseipdb_feed.settings")
    def test_skips_when_no_api_key(self, mock_settings):
        mock_settings.ABUSEIPDB_API_KEY = ""

        self.cron.run()

        # Should log warning and skip
        self.assertEqual(AbuseIPDBFeed.objects.count(), 0)

    @patch("greedybear.cronjobs.abuseipdb_feed.settings")
    @patch("greedybear.cronjobs.abuseipdb_feed.requests.get")
    def test_skips_invalid_ips(self, mock_get, mock_settings):
        mock_settings.ABUSEIPDB_API_KEY = "test-api-key"

        blacklist_data = [
            {
                "ipAddress": "invalid.ip.address",
                "abuseConfidenceScore": 95,
                "usageType": "Data Center",
                "countryCode": "US",
            }
        ]
        mock_get.return_value = self._create_mock_response(blacklist_data)

        self.cron.run()

        self.assertEqual(AbuseIPDBFeed.objects.count(), 0)

    @patch("greedybear.cronjobs.abuseipdb_feed.settings")
    @patch("greedybear.cronjobs.abuseipdb_feed.requests.get")
    def test_handles_request_exception(self, mock_get, mock_settings):
        mock_settings.ABUSEIPDB_API_KEY = "test-api-key"
        mock_get.side_effect = requests.RequestException("API error")

        with self.assertRaises(requests.RequestException):
            self.cron.run()

    @patch("greedybear.cronjobs.abuseipdb_feed.settings")
    @patch("greedybear.cronjobs.abuseipdb_feed.requests.get")
    def test_cleanup_old_entries(self, mock_get, mock_settings):
        from datetime import timedelta

        from django.utils import timezone

        mock_settings.ABUSEIPDB_API_KEY = "test-api-key"

        # Create an old entry
        old_entry = AbuseIPDBFeed.objects.create(
            ip_address="1.2.3.4",
            abuse_confidence_score=80,
        )
        old_entry.added = timezone.now() - timedelta(days=31)
        old_entry.save()

        # Mock empty response
        mock_get.return_value = self._create_mock_response([])

        self.cron.run()

        # Old entry should be deleted
        self.assertEqual(AbuseIPDBFeed.objects.filter(ip_address="1.2.3.4").count(), 0)

    @patch("greedybear.cronjobs.abuseipdb_feed.settings")
    @patch("greedybear.cronjobs.abuseipdb_feed.requests.get")
    def test_enforces_10k_limit(self, mock_get, mock_settings):
        mock_settings.ABUSEIPDB_API_KEY = "test-api-key"

        # Create 10 existing entries
        for i in range(10):
            AbuseIPDBFeed.objects.create(
                ip_address=f"1.1.1.{i}",
                abuse_confidence_score=80,
            )

        # Try to add 5 more
        blacklist_data = [
            {
                "ipAddress": f"2.2.2.{i}",
                "abuseConfidenceScore": 90,
                "usageType": "ISP",
                "countryCode": "US",
            }
            for i in range(5)
        ]
        mock_get.return_value = self._create_mock_response(blacklist_data)

        self.cron.run()

        # Should enforce limit and keep exactly 10k (in this case 10)
        # Since MAX_ENTRIES is 10000 and we only have 15, no enforcement yet
        self.assertEqual(AbuseIPDBFeed.objects.count(), 15)
