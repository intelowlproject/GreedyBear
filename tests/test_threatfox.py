from unittest.mock import Mock, patch

import requests

from greedybear.cronjobs.repositories import ThreatFoxRepository
from greedybear.cronjobs.threatfox_feed import ThreatFoxCron
from greedybear.models import ThreatFoxFeed
from tests import CustomTestCase


class TestThreatFoxRepository(CustomTestCase):
    """Tests for ThreatFoxRepository."""

    def setUp(self):
        self.repo = ThreatFoxRepository()

    def test_get_or_create_creates_new_entry(self):
        entry, created = self.repo.get_or_create(
            ip_address="1.2.3.4",
            malware="win.mirai",
            malware_printable="Mirai",
            threat_type="botnet_cc",
            confidence_level=85,
            tags=["botnet", "mirai"],
        )

        self.assertTrue(created)
        self.assertEqual(entry.ip_address, "1.2.3.4")
        self.assertEqual(entry.malware, "win.mirai")
        self.assertEqual(entry.malware_printable, "Mirai")
        self.assertEqual(entry.threat_type, "botnet_cc")
        self.assertEqual(entry.confidence_level, 85)
        self.assertEqual(entry.tags, ["botnet", "mirai"])

    def test_get_or_create_returns_existing(self):
        ThreatFoxFeed.objects.create(
            ip_address="5.6.7.8",
            malware="win.emotet",
            malware_printable="Emotet",
        )

        entry, created = self.repo.get_or_create(ip_address="5.6.7.8", malware="win.emotet")

        self.assertFalse(created)
        self.assertEqual(entry.ip_address, "5.6.7.8")

    def test_get_by_ip(self):
        ThreatFoxFeed.objects.create(ip_address="1.1.1.1", malware="win.test1")
        ThreatFoxFeed.objects.create(ip_address="1.1.1.1", malware="win.test2")
        ThreatFoxFeed.objects.create(ip_address="2.2.2.2", malware="win.test3")

        entries = self.repo.get_by_ip("1.1.1.1")

        self.assertEqual(len(entries), 2)
        malware_names = [e.malware for e in entries]
        self.assertIn("win.test1", malware_names)
        self.assertIn("win.test2", malware_names)

    def test_clear_all(self):
        ThreatFoxFeed.objects.create(ip_address="1.1.1.1", malware="win.test1")
        ThreatFoxFeed.objects.create(ip_address="2.2.2.2", malware="win.test2")

        count = self.repo.clear_all()

        self.assertEqual(count, 2)
        self.assertEqual(ThreatFoxFeed.objects.count(), 0)

    def test_count(self):
        ThreatFoxFeed.objects.create(ip_address="1.1.1.1", malware="win.test1")
        ThreatFoxFeed.objects.create(ip_address="2.2.2.2", malware="win.test2")

        count = self.repo.count()

        self.assertEqual(count, 2)

    def test_cleanup_old_entries(self):
        from datetime import timedelta

        from django.utils import timezone

        # Create entries with different ages
        ThreatFoxFeed.objects.create(ip_address="1.1.1.1", malware="win.recent")

        old = ThreatFoxFeed.objects.create(ip_address="2.2.2.2", malware="win.old")
        old.added = timezone.now() - timedelta(days=31)
        old.save()

        deleted = self.repo.cleanup_old_entries(days=30)

        self.assertEqual(deleted, 1)
        self.assertEqual(ThreatFoxFeed.objects.count(), 1)
        self.assertTrue(ThreatFoxFeed.objects.filter(ip_address="1.1.1.1").exists())


class TestThreatFoxCron(CustomTestCase):
    """Tests for ThreatFoxCron."""

    def setUp(self):
        self.repo = ThreatFoxRepository()
        self.cron = ThreatFoxCron(threatfox_repo=self.repo)

    def _create_mock_response(self, iocs_data):
        """Helper to create a mock response."""
        mock_response = Mock()
        mock_response.json.return_value = {"query_status": "ok", "data": iocs_data}
        mock_response.raise_for_status = Mock()
        return mock_response

    @patch("greedybear.cronjobs.threatfox_feed.requests.post")
    def test_downloads_and_stores_ip_iocs(self, mock_post):
        iocs_data = [
            {
                "ioc": "1.2.3.4",
                "ioc_type": "ip",
                "malware": "win.mirai",
                "malware_printable": "Mirai",
                "threat_type": "botnet_cc",
                "confidence_level": 85,
                "tags": ["botnet"],
            },
            {
                "ioc": "5.6.7.8:443",
                "ioc_type": "ip:port",
                "malware": "win.cobalt_strike",
                "malware_printable": "Cobalt Strike",
                "threat_type": "botnet_cc",
                "confidence_level": 90,
                "tags": None,
            },
        ]
        mock_post.return_value = self._create_mock_response(iocs_data)

        self.cron.run()

        self.assertEqual(ThreatFoxFeed.objects.count(), 2)
        entry1 = ThreatFoxFeed.objects.get(ip_address="1.2.3.4")
        self.assertEqual(entry1.malware, "win.mirai")
        self.assertEqual(entry1.tags, ["botnet"])

        entry2 = ThreatFoxFeed.objects.get(ip_address="5.6.7.8")
        self.assertEqual(entry2.malware, "win.cobalt_strike")

    @patch("greedybear.cronjobs.threatfox_feed.requests.post")
    def test_extracts_ip_from_url(self, mock_post):
        iocs_data = [
            {
                "ioc": "http://192.168.1.100/malware.exe",
                "ioc_type": "url",
                "malware": "win.test",
                "malware_printable": "Test Malware",
                "threat_type": "payload_delivery",
                "confidence_level": 75,
                "tags": [],
            }
        ]
        mock_post.return_value = self._create_mock_response(iocs_data)

        self.cron.run()

        # Should not store private IPs
        self.assertEqual(ThreatFoxFeed.objects.count(), 0)

    @patch("greedybear.cronjobs.threatfox_feed.requests.post")
    def test_skips_invalid_ips(self, mock_post):
        iocs_data = [
            {
                "ioc": "999.999.999.999",
                "ioc_type": "ip",
                "malware": "win.test",
                "malware_printable": "Test",
                "threat_type": "botnet_cc",
                "confidence_level": 50,
                "tags": [],
            }
        ]
        mock_post.return_value = self._create_mock_response(iocs_data)

        self.cron.run()

        self.assertEqual(ThreatFoxFeed.objects.count(), 0)

    @patch("greedybear.cronjobs.threatfox_feed.requests.post")
    def test_handles_api_error_status(self, mock_post):
        mock_response = Mock()
        mock_response.json.return_value = {"query_status": "error", "data": []}
        mock_post.return_value = mock_response

        self.cron.run()

        # Should log warning and return without processing
        self.assertEqual(ThreatFoxFeed.objects.count(), 0)

    @patch("greedybear.cronjobs.threatfox_feed.requests.post")
    def test_handles_request_exception(self, mock_post):
        mock_post.side_effect = requests.RequestException("Connection error")

        with self.assertRaises(requests.RequestException):
            self.cron.run()

    @patch("greedybear.cronjobs.threatfox_feed.requests.post")
    def test_cleanup_old_entries(self, mock_post):
        from datetime import timedelta

        from django.utils import timezone

        # Create an old entry
        old_entry = ThreatFoxFeed.objects.create(
            ip_address="1.2.3.4",
            malware="win.old",
        )
        old_entry.added = timezone.now() - timedelta(days=31)
        old_entry.save()

        # Mock empty response
        mock_post.return_value = self._create_mock_response([])

        self.cron.run()

        # Old entry should be deleted
        self.assertEqual(ThreatFoxFeed.objects.filter(ip_address="1.2.3.4").count(), 0)

    @patch("greedybear.cronjobs.threatfox_feed.requests.post")
    def test_run_skips_when_api_key_missing(self, mock_post):
        """Test that run() returns early if API key is not configured."""
        with self.settings(THREATFOX_API_KEY=""):
            self.cron.run()
            mock_post.assert_not_called()
