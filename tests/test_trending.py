from datetime import datetime, timedelta
from unittest.mock import patch

from django.test import override_settings

from greedybear.cronjobs.trending import TrendingAttackersCron
from greedybear.models import AttackerActivityBucket, TrendingAttackerSnapshot
from tests import CustomTestCase


class TestTrendingAttackersCron(CustomTestCase):
    def setUp(self):
        super().setUp()
        self.cron = TrendingAttackersCron()

    def _run_at(self, now: datetime):
        with patch("greedybear.cronjobs.trending.timezone.now", return_value=now):
            self.cron.run()

    @override_settings(TRENDING_PRECOMPUTE_WINDOWS_MINUTES=[60], TRENDING_PRECOMPUTE_LIMIT=50, TRENDING_BUCKET_RETENTION_HOURS=72)
    def test_materializes_and_replaces_snapshots(self):
        now = datetime(2026, 3, 20, 10, 30, 0)
        TrendingAttackerSnapshot.objects.create(
            window_minutes=60,
            feed_type="all",
            attacker_ip="9.9.9.9",
            current_interactions=1,
            previous_interactions=1,
            interaction_delta=0,
            growth_score=0.0,
            current_rank=1,
            previous_rank=1,
            rank_delta=0,
        )
        AttackerActivityBucket.objects.create(
            attacker_ip="1.1.1.1",
            feed_type="cowrie",
            bucket_start=datetime(2026, 3, 20, 9, 0, 0),
            interaction_count=5,
        )
        AttackerActivityBucket.objects.create(
            attacker_ip="1.1.1.1",
            feed_type="cowrie",
            bucket_start=datetime(2026, 3, 20, 8, 0, 0),
            interaction_count=2,
        )

        self._run_at(now)

        self.assertFalse(TrendingAttackerSnapshot.objects.filter(attacker_ip="9.9.9.9").exists())
        snapshot = TrendingAttackerSnapshot.objects.get(window_minutes=60, feed_type="all", attacker_ip="1.1.1.1")
        self.assertEqual(snapshot.current_interactions, 5)
        self.assertEqual(snapshot.previous_interactions, 2)

    @override_settings(TRENDING_PRECOMPUTE_WINDOWS_MINUTES=[60], TRENDING_PRECOMPUTE_LIMIT=50, TRENDING_BUCKET_RETENTION_HOURS=24)
    def test_retention_deletes_only_stale_buckets(self):
        now = datetime(2026, 3, 20, 10, 30, 0)
        stale = AttackerActivityBucket.objects.create(
            attacker_ip="2.2.2.2",
            feed_type="cowrie",
            bucket_start=now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=30),
            interaction_count=1,
        )
        fresh = AttackerActivityBucket.objects.create(
            attacker_ip="3.3.3.3",
            feed_type="cowrie",
            bucket_start=now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=2),
            interaction_count=1,
        )

        self._run_at(now)

        self.assertFalse(AttackerActivityBucket.objects.filter(pk=stale.pk).exists())
        self.assertTrue(AttackerActivityBucket.objects.filter(pk=fresh.pk).exists())

    @override_settings(TRENDING_PRECOMPUTE_WINDOWS_MINUTES=[60], TRENDING_PRECOMPUTE_LIMIT=50, TRENDING_BUCKET_RETENTION_HOURS=0)
    def test_invalid_retention_raises(self):
        now = datetime(2026, 3, 20, 10, 30, 0)
        AttackerActivityBucket.objects.create(
            attacker_ip="4.4.4.4",
            feed_type="cowrie",
            bucket_start=now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=200),
            interaction_count=1,
        )

        with self.assertRaises(ValueError):
            self._run_at(now)
