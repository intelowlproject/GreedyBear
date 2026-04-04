from unittest.mock import patch

from django.core.cache import cache
from rest_framework import status
from rest_framework.test import APIClient

from tests import CustomTestCase


class FeedsThrottleTestCase(CustomTestCase):
    """Tests that rate limiting is applied to feeds endpoints."""

    def setUp(self):
        super().setUp()
        cache.clear()
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)

    @patch("api.throttles.FeedsAdvancedThrottle.get_rate", return_value="1/minute")
    def test_feeds_advanced_throttled(self, mock_rate):
        """Verify feeds_advanced returns 429 after exceeding the rate limit."""
        response = self.client.get("/api/feeds/advanced/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = self.client.get("/api/feeds/advanced/")
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    @patch("api.throttles.FeedsAdvancedThrottle.get_rate", return_value="1/minute")
    def test_feeds_asn_throttled(self, mock_rate):
        """Verify feeds_asn returns 429 after exceeding the rate limit."""
        response = self.client.get("/api/feeds/asn/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = self.client.get("/api/feeds/asn/")
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    @patch("api.throttles.FeedsThrottle.get_rate", return_value="1/minute")
    def test_feeds_pagination_throttled(self, mock_rate):
        """Verify feeds_pagination returns 429 after exceeding the rate limit."""
        response = self.client.get("/api/feeds/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = self.client.get("/api/feeds/")
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    @patch("api.throttles.FeedsThrottle.get_rate", return_value="1/minute")
    def test_feeds_legacy_throttled(self, mock_rate):
        """Verify legacy feeds endpoint returns 429 after exceeding the rate limit."""
        url = "/api/feeds/all/all/recent.json"
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    @patch("api.throttles.FeedsThrottle.get_rate", return_value="1/minute")
    def test_feeds_trending_throttled(self, mock_rate):
        """Verify feeds_trending returns 429 after exceeding the trending rate limit."""
        client = APIClient()
        response = client.get("/api/feeds/trending/?window_minutes=60&limit=10&feed_type=all")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = client.get("/api/feeds/trending/?window_minutes=60&limit=10&feed_type=all")
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    @patch("api.throttles.FeedsThrottle.get_rate", return_value="1/minute")
    def test_feeds_trending_shares_feeds_scope(self, mock_feeds_rate):
        """Verify feeds and feeds_trending share the same throttle scope."""
        client = APIClient()

        trending_response = client.get("/api/feeds/trending/?window_minutes=60&limit=10&feed_type=all")
        self.assertEqual(trending_response.status_code, status.HTTP_200_OK)

        feeds_response = client.get("/api/feeds/")
        self.assertEqual(feeds_response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

        trending_response = client.get("/api/feeds/trending/?window_minutes=60&limit=10&feed_type=all")
        self.assertEqual(trending_response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_feeds_advanced_within_limit(self):
        """Verify feeds_advanced succeeds when within the rate limit."""
        response = self.client.get("/api/feeds/advanced/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_feeds_asn_within_limit(self):
        """Verify feeds_asn succeeds when within the rate limit."""
        response = self.client.get("/api/feeds/asn/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_feeds_unauthenticated_access(self):
        """Verify public feeds endpoints are accessible without authentication."""
        client = APIClient()
        response = client.get("/api/feeds/all/all/recent.json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_feeds_pagination_unauthenticated_access(self):
        """Verify public feeds pagination endpoint is accessible without authentication."""
        client = APIClient()
        response = client.get("/api/feeds/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_feeds_advanced_unauthenticated_rejected(self):
        """Verify authenticated feeds_advanced endpoint rejects unauthenticated requests."""
        client = APIClient()
        response = client.get("/api/feeds/advanced/")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_feeds_asn_unauthenticated_rejected(self):
        """Verify authenticated feeds_asn endpoint rejects unauthenticated requests."""
        client = APIClient()
        response = client.get("/api/feeds/asn/")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_feeds_trending_within_limit(self):
        """Verify feeds_trending succeeds when within the default rate limit."""
        response = self.client.get("/api/feeds/trending/?window_minutes=60&limit=10&feed_type=all")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
