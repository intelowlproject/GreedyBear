from datetime import datetime
from unittest.mock import patch

from django.test import override_settings

from greedybear.cronjobs.repositories.trending_bucket import TrendingBucketRepository
from greedybear.cronjobs.trending import TrendingAttackersCron, update_activity_buckets_from_hits
from greedybear.models import AttackerActivityBucket
from tests import CustomTestCase


class UpdateActivityBucketsFromHitsTestCase(CustomTestCase):
    def test_upsert_increments_existing_bucket_and_creates_missing_bucket(self):
        AttackerActivityBucket.objects.create(
            attacker_ip="1.1.1.1",
            feed_type="cowrie",
            bucket_start=datetime(2026, 3, 20, 9, 0),
            interaction_count=3,
        )

        unique_keys = update_activity_buckets_from_hits(
            [
                {"src_ip": "1.1.1.1", "type": "Cowrie", "@timestamp": "2026-03-20T09:15:00"},
                {"src_ip": "1.1.1.1", "type": "cowrie", "@timestamp": "2026-03-20T09:50:00"},
                {"src_ip": "2.2.2.2", "type": "Heralding", "@timestamp": "2026-03-20T09:10:00"},
            ]
        )

        self.assertEqual(unique_keys, 2)

        existing_bucket = AttackerActivityBucket.objects.get(
            attacker_ip="1.1.1.1",
            feed_type="cowrie",
            bucket_start=datetime(2026, 3, 20, 9, 0),
        )
        self.assertEqual(existing_bucket.interaction_count, 5)

        created_bucket = AttackerActivityBucket.objects.get(
            attacker_ip="2.2.2.2",
            feed_type="heralding",
            bucket_start=datetime(2026, 3, 20, 9, 0),
        )
        self.assertEqual(created_bucket.interaction_count, 1)

    def test_invalid_hits_are_ignored(self):
        unique_keys = update_activity_buckets_from_hits(
            [
                {"src_ip": "", "type": "cowrie", "@timestamp": "2026-03-20T09:15:00"},
                {"src_ip": "999.999.999.999", "type": "cowrie", "@timestamp": "2026-03-20T09:15:00"},
                {"src_ip": "3.3.3.3", "type": "", "@timestamp": "2026-03-20T09:15:00"},
                {"src_ip": "3.3.3.3", "type": "cowrie"},
            ]
        )

        self.assertEqual(unique_keys, 0)
        self.assertEqual(AttackerActivityBucket.objects.count(), 0)

    def test_non_global_ip_hits_are_ignored(self):
        unique_keys = update_activity_buckets_from_hits(
            [
                {"src_ip": "10.0.0.1", "type": "cowrie", "@timestamp": "2026-03-20T09:15:00"},
                {"src_ip": "127.0.0.1", "type": "cowrie", "@timestamp": "2026-03-20T09:15:00"},
                {"src_ip": "224.0.0.1", "type": "cowrie", "@timestamp": "2026-03-20T09:15:00"},
                {"src_ip": "169.254.1.1", "type": "cowrie", "@timestamp": "2026-03-20T09:15:00"},
                {"src_ip": "240.0.0.1", "type": "cowrie", "@timestamp": "2026-03-20T09:15:00"},
                {"src_ip": "8.8.8.8", "type": "cowrie", "@timestamp": "2026-03-20T09:15:00"},
            ]
        )

        self.assertEqual(unique_keys, 1)
        self.assertEqual(AttackerActivityBucket.objects.count(), 1)
        self.assertTrue(AttackerActivityBucket.objects.filter(attacker_ip="8.8.8.8").exists())

    def test_upsert_uses_multiple_batches_for_large_counter_sets(self):
        counters = {
            ("10.0.0.1", "cowrie", datetime(2026, 3, 20, 9, 0)): 1,
            ("10.0.0.2", "cowrie", datetime(2026, 3, 20, 9, 0)): 1,
            ("10.0.0.3", "cowrie", datetime(2026, 3, 20, 9, 0)): 1,
            ("10.0.0.4", "cowrie", datetime(2026, 3, 20, 9, 0)): 1,
            ("10.0.0.5", "cowrie", datetime(2026, 3, 20, 9, 0)): 1,
        }

        repository = TrendingBucketRepository()
        with patch.object(TrendingBucketRepository, "UPSERT_BATCH_SIZE", 2):
            with patch("greedybear.cronjobs.repositories.trending_bucket.connection.cursor") as mock_cursor_factory:
                mock_cursor = mock_cursor_factory.return_value.__enter__.return_value
                inserted = repository.upsert_bucket_counts(counters)

        self.assertEqual(inserted, 5)
        self.assertEqual(mock_cursor.execute.call_count, 3)


class TrendingAttackersCronTestCase(CustomTestCase):
    def setUp(self):
        super().setUp()
        self.cron = TrendingAttackersCron()

    @override_settings(
        TRENDING_BUCKET_RETENTION_HOURS=2,
        TRENDING_MAX_WINDOW_MINUTES=60,
    )
    def test_run_applies_bucket_retention_cleanup(self):
        AttackerActivityBucket.objects.bulk_create(
            [
                AttackerActivityBucket(
                    attacker_ip="2.2.2.2",
                    feed_type="cowrie",
                    bucket_start=datetime(2026, 3, 20, 7, 0),
                    interaction_count=1,
                ),
                AttackerActivityBucket(
                    attacker_ip="3.3.3.3",
                    feed_type="cowrie",
                    bucket_start=datetime(2026, 3, 20, 9, 0),
                    interaction_count=1,
                ),
            ]
        )

        with patch("greedybear.cronjobs.trending.timezone.now", return_value=datetime(2026, 3, 20, 10, 30, 0)):
            self.cron.run()

        self.assertFalse(AttackerActivityBucket.objects.filter(attacker_ip="2.2.2.2").exists())
        self.assertTrue(AttackerActivityBucket.objects.filter(attacker_ip="3.3.3.3").exists())

    @override_settings(
        TRENDING_BUCKET_RETENTION_HOURS=0,
    )
    def test_run_raises_on_invalid_retention_hours(self):
        with patch("greedybear.cronjobs.trending.timezone.now", return_value=datetime(2026, 3, 20, 10, 30, 0)):
            with self.assertRaises(ValueError):
                self.cron.run()

    @override_settings(
        TRENDING_BUCKET_RETENTION_HOURS=1,
        TRENDING_MAX_WINDOW_MINUTES=60,
    )
    def test_run_raises_when_retention_cannot_cover_two_windows(self):
        with patch("greedybear.cronjobs.trending.timezone.now", return_value=datetime(2026, 3, 20, 10, 30, 0)):
            with self.assertRaises(ValueError):
                self.cron.run()

    @override_settings(
        TRENDING_BUCKET_RETENTION_HOURS=1,
        TRENDING_MAX_WINDOW_MINUTES=120,
    )
    def test_run_raises_when_max_window_exceeds_retention_horizon(self):
        with patch("greedybear.cronjobs.trending.timezone.now", return_value=datetime(2026, 3, 20, 10, 30, 0)):
            with self.assertRaises(ValueError):
                self.cron.run()
