from datetime import datetime

from django.test import override_settings
from rest_framework.test import APIClient

from greedybear.models import AttackerActivityBucket, TrendingAttackerSnapshot
from tests import CustomTestCase


class FeedsTrendingViewTestCase(CustomTestCase):
    def setUp(self):
        super().setUp()
        self.client = APIClient()
        self.client.force_authenticate(user=self.superuser)

    def test_200_trending_with_custom_window(self):
        now = datetime(2026, 3, 20, 10, 30, 0)
        AttackerActivityBucket.objects.bulk_create(
            [
                AttackerActivityBucket(attacker_ip="1.1.1.1", feed_type="cowrie", bucket_start=datetime(2026, 3, 20, 8, 0), interaction_count=2),
                AttackerActivityBucket(attacker_ip="1.1.1.1", feed_type="cowrie", bucket_start=datetime(2026, 3, 20, 9, 0), interaction_count=1),
                AttackerActivityBucket(attacker_ip="2.2.2.2", feed_type="cowrie", bucket_start=datetime(2026, 3, 20, 8, 0), interaction_count=1),
                AttackerActivityBucket(attacker_ip="1.1.1.1", feed_type="cowrie", bucket_start=datetime(2026, 3, 20, 6, 0), interaction_count=1),
                AttackerActivityBucket(attacker_ip="3.3.3.3", feed_type="cowrie", bucket_start=datetime(2026, 3, 20, 5, 0), interaction_count=3),
            ]
        )

        with self.settings(TRENDING_PRECOMPUTE_WINDOWS_MINUTES=[24 * 60, 7 * 24 * 60]):
            with self.subTest("aggregated endpoint"):
                from unittest.mock import patch

                with patch("api.views.feeds.timezone.now", return_value=now):
                    response = self.client.get("/api/feeds/trending/?window_minutes=180&limit=10&feed_type=cowrie")
        self.assertEqual(response.status_code, 200)

        payload = response.json()
        self.assertEqual(payload["window_minutes"], 180)
        self.assertEqual(payload["feed_type"], ["cowrie"])
        self.assertEqual(payload["data_source"], "aggregated")
        self.assertEqual(payload["count"], 3)

        attackers = {item["attacker_ip"]: item for item in payload["attackers"]}

        self.assertEqual(attackers["1.1.1.1"]["current_interactions"], 3)
        self.assertEqual(attackers["1.1.1.1"]["previous_interactions"], 1)
        self.assertEqual(attackers["1.1.1.1"]["rank_delta"], 1)

        self.assertEqual(attackers["2.2.2.2"]["current_rank"], 2)
        self.assertIsNone(attackers["2.2.2.2"]["previous_rank"])

        self.assertIsNone(attackers["3.3.3.3"]["current_rank"])
        self.assertEqual(attackers["3.3.3.3"]["previous_rank"], 1)
        self.assertEqual(attackers["3.3.3.3"]["rank_delta"], -1)

    def test_200_trending_anonymous_access(self):
        response = APIClient().get("/api/feeds/trending/?window_minutes=60&limit=10&feed_type=all")
        self.assertEqual(response.status_code, 200)

    @override_settings(TRENDING_PRECOMPUTE_WINDOWS_MINUTES=[24 * 60])
    def test_200_trending_uses_precomputed_snapshot(self):
        TrendingAttackerSnapshot.objects.create(
            window_minutes=24 * 60,
            feed_type="all",
            attacker_ip="4.4.4.4",
            current_interactions=10,
            previous_interactions=2,
            interaction_delta=8,
            growth_score=4.0,
            current_rank=1,
            previous_rank=3,
            rank_delta=2,
        )

        from unittest.mock import patch

        with patch("api.views.feeds.timezone.now", return_value=datetime(2026, 3, 20, 10, 30, 0)):
            response = self.client.get("/api/feeds/trending/?window_minutes=1440&limit=10&feed_type=all")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["data_source"], "precomputed")
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["attackers"][0]["attacker_ip"], "4.4.4.4")

    def test_400_trending_invalid_window(self):
        response = self.client.get("/api/feeds/trending/?window_minutes=5")
        self.assertEqual(response.status_code, 400)

    def test_400_trending_window_not_multiple_of_60(self):
        response = self.client.get("/api/feeds/trending/?window_minutes=90")
        self.assertEqual(response.status_code, 400)

    @override_settings(TRENDING_MAX_WINDOW_MINUTES=120)
    def test_400_trending_window_larger_than_max(self):
        response = self.client.get("/api/feeds/trending/?window_minutes=180")
        self.assertEqual(response.status_code, 400)

    def test_200_trending_accepts_mixed_case_feed_type(self):
        now = datetime(2026, 3, 20, 10, 30, 0)
        AttackerActivityBucket.objects.create(
            attacker_ip="9.9.9.9",
            feed_type="cowrie",
            bucket_start=datetime(2026, 3, 20, 9, 0),
            interaction_count=5,
        )

        from unittest.mock import patch

        with patch("api.views.feeds.timezone.now", return_value=now):
            response = self.client.get("/api/feeds/trending/?window_minutes=60&limit=10&feed_type=CoWrIe")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["feed_type"], ["cowrie"])

    def test_200_trending_multi_feed_uses_aggregated(self):
        now = datetime(2026, 3, 20, 10, 30, 0)
        AttackerActivityBucket.objects.bulk_create(
            [
                AttackerActivityBucket(attacker_ip="8.8.8.8", feed_type="cowrie", bucket_start=datetime(2026, 3, 20, 9, 0), interaction_count=2),
                AttackerActivityBucket(attacker_ip="8.8.8.8", feed_type="heralding", bucket_start=datetime(2026, 3, 20, 9, 0), interaction_count=3),
            ]
        )

        from unittest.mock import patch

        with patch("api.views.feeds.timezone.now", return_value=now):
            response = self.client.get("/api/feeds/trending/?window_minutes=60&limit=10&feed_type=cowrie,heralding")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["data_source"], "aggregated")
        self.assertEqual(payload["count"], 1)
