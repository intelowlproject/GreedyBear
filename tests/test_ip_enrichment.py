from unittest.mock import Mock, patch

import requests

from greedybear.cronjobs.ip_enrichment import IPEnrichmentCron
from greedybear.cronjobs.repositories.ip_enrichment import TagRepository
from greedybear.models import IOC, Tag
from tests import CustomTestCase


class TestTagRepository(CustomTestCase):
    """Test cases for TagRepository."""

    def setUp(self):
        """Set up test fixtures."""
        self.repo = TagRepository()
        # Create a test IOC
        self.ioc = IOC.objects.create(name="1.2.3.4", type="ip")

    def test_create_tags_normalizes_names(self):
        """Test that tag names are normalized to lowercase."""
        # Act
        tags = self.repo.create_tags(
            ioc=self.ioc,
            tags=["Mirai", "BOTNET", "High-Risk"],
            source="abuseipdb",
        )

        # Assert
        self.assertEqual(len(tags), 3)
        self.assertEqual(tags[0].name, "mirai")
        self.assertEqual(tags[1].name, "botnet")
        self.assertEqual(tags[2].name, "high-risk")

    def test_create_tags_skips_empty(self):
        """Test that empty tag names are skipped."""
        # Act
        tags = self.repo.create_tags(
            ioc=self.ioc,
            tags=["mirai", "", "  ", "botnet"],
            source="abuseipdb",
        )

        # Assert
        self.assertEqual(len(tags), 2)
        self.assertEqual(tags[0].name, "mirai")
        self.assertEqual(tags[1].name, "botnet")

    def test_create_tags_avoids_duplicates(self):
        """Test that get_or_create prevents duplicate tags."""
        # Act - create same tags twice
        tags1 = self.repo.create_tags(
            ioc=self.ioc,
            tags=["mirai", "botnet"],
            source="abuseipdb",
        )
        tags2 = self.repo.create_tags(
            ioc=self.ioc,
            tags=["mirai", "botnet"],
            source="abuseipdb",
        )

        # Assert
        self.assertEqual(len(tags1), 2)
        self.assertEqual(len(tags2), 2)
        # Should have same IDs (not duplicated)
        self.assertEqual(tags1[0].id, tags2[0].id)
        self.assertEqual(tags1[1].id, tags2[1].id)
        # Verify only 2 tags in database
        self.assertEqual(Tag.objects.filter(ioc=self.ioc).count(), 2)


class TestIPEnrichmentCron(CustomTestCase):
    """Test cases for IPEnrichmentCron."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_tag_repo = Mock()
        self.mock_ioc_repo = Mock()
        self.cron = IPEnrichmentCron(tag_repo=self.mock_tag_repo, ioc_repo=self.mock_ioc_repo)

    @patch("greedybear.cronjobs.ip_enrichment.os.getenv")
    @patch("greedybear.cronjobs.ip_enrichment.requests.get")
    @patch("greedybear.cronjobs.ip_enrichment.requests.post")
    def test_run_success(self, mock_post, mock_get, mock_getenv):
        """Test successful IP enrichment from both sources."""
        # Arrange
        mock_getenv.return_value = "test-api-key"

        # Mock IOC queryset (backfill all IOCs)
        mock_ioc = Mock()
        mock_ioc.name = "1.2.3.4"
        self.mock_ioc_repo.get_queryset.return_value = [mock_ioc]

        # Mock AbuseIPDB response
        mock_abuse_response = Mock()
        mock_abuse_response.json.return_value = {
            "data": {
                "abuseConfidenceScore": 95,
                "usageType": "Data Center",
            }
        }
        mock_get.return_value = mock_abuse_response

        # Mock Abuse.ch response
        mock_threat_response = Mock()
        mock_threat_response.json.return_value = {
            "query_status": "ok",
            "data": [
                {
                    "malware": "Mirai",
                    "tags": ["botnet", "elf"],
                    "confidence_level": 80,
                }
            ],
        }
        mock_post.return_value = mock_threat_response

        # Act
        self.cron.run()

        # Assert - create_tags should be called twice (AbuseIPDB + Abuse.ch)
        self.assertEqual(self.mock_tag_repo.create_tags.call_count, 2)

    @patch("greedybear.cronjobs.ip_enrichment.os.getenv")
    def test_abuseipdb_no_api_key(self, mock_getenv):
        """Test AbuseIPDB check without API key."""
        # Arrange
        mock_getenv.return_value = None

        # Act
        result = self.cron._check_abuseipdb("1.2.3.4")

        # Assert
        self.assertIsNone(result)

    @patch("greedybear.cronjobs.ip_enrichment.os.getenv")
    @patch("greedybear.cronjobs.ip_enrichment.requests.get")
    def test_abuseipdb_request_failure(self, mock_get, mock_getenv):
        """Test handling of AbuseIPDB request failures."""
        # Arrange
        mock_getenv.return_value = "test-key"
        mock_get.side_effect = requests.RequestException("Network error")

        # Act
        result = self.cron._check_abuseipdb("1.2.3.4")

        # Assert
        self.assertIsNone(result)

    @patch("greedybear.cronjobs.ip_enrichment.requests.post")
    def test_abusech_request_failure(self, mock_post):
        """Test handling of Abuse.ch request failures."""
        # Arrange
        mock_post.side_effect = requests.RequestException("Network error")

        # Act
        result = self.cron._check_abusech("1.2.3.4")

        # Assert
        self.assertIsNone(result)

    @patch("greedybear.cronjobs.ip_enrichment.requests.post")
    def test_abusech_no_results(self, mock_post):
        """Test Abuse.ch when no threat data is found."""
        # Arrange
        mock_response = Mock()
        mock_response.json.return_value = {"query_status": "no_result"}
        mock_post.return_value = mock_response

        # Act
        result = self.cron._check_abusech("1.2.3.4")

        # Assert
        self.assertIsNone(result)
