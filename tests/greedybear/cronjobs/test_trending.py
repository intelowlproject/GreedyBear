from datetime import datetime
from unittest.mock import patch

from django.test import override_settings

from greedybear.cronjobs.trending import TrendingAttackersCron, update_activity_buckets_from_hits
from greedybear.models import AttackerActivityBucket, GeneralHoneypot, TrendingAttackerSnapshot
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


class TrendingAttackersCronTestCase(CustomTestCase):
    def setUp(self):
        super().setUp()
        self.cron = TrendingAttackersCron()

    @override_settings(
        TRENDING_PRECOMPUTE_WINDOWS_MINUTES=[60],
        TRENDING_PRECOMPUTE_LIMIT=10,
        TRENDING_BUCKET_RETENTION_HOURS=24,
    )
    def test_run_materializes_snapshots_and_replaces_existing_rows(self):
        GeneralHoneypot.objects.get_or_create(name="Cowrie", defaults={"active": True})

        TrendingAttackerSnapshot.objects.create(
            window_minutes=60,
            feed_type="all",
            attacker_ip="9.9.9.9",
            current_interactions=100,
            previous_interactions=1,
            interaction_delta=99,
            growth_score=99.0,
            current_rank=1,
            previous_rank=2,
            rank_delta=1,
        )

        AttackerActivityBucket.objects.bulk_create(
            [
                AttackerActivityBucket(
                    attacker_ip="1.1.1.1",
                    feed_type="cowrie",
                    bucket_start=datetime(2026, 3, 20, 9, 0),
                    interaction_count=5,
                ),
                AttackerActivityBucket(
                    attacker_ip="1.1.1.1",
                    feed_type="cowrie",
                    bucket_start=datetime(2026, 3, 20, 8, 0),
                    interaction_count=1,
                ),
            ]
        )

        with patch("greedybear.cronjobs.trending.timezone.now", return_value=datetime(2026, 3, 20, 10, 30, 0)):
            self.cron.run()

        self.assertFalse(TrendingAttackerSnapshot.objects.filter(attacker_ip="9.9.9.9").exists())
        self.assertEqual(TrendingAttackerSnapshot.objects.filter(window_minutes=60, feed_type="all").count(), 1)
        self.assertEqual(TrendingAttackerSnapshot.objects.filter(window_minutes=60, feed_type="cowrie").count(), 1)

        all_snapshot = TrendingAttackerSnapshot.objects.get(window_minutes=60, feed_type="all")
        self.assertEqual(all_snapshot.attacker_ip, "1.1.1.1")
        self.assertEqual(all_snapshot.current_interactions, 5)

        cowrie_snapshot = TrendingAttackerSnapshot.objects.get(window_minutes=60, feed_type="cowrie")
        self.assertEqual(cowrie_snapshot.attacker_ip, "1.1.1.1")
        self.assertEqual(cowrie_snapshot.current_interactions, 5)

    @override_settings(
        TRENDING_PRECOMPUTE_WINDOWS_MINUTES=[60],
        TRENDING_PRECOMPUTE_LIMIT=10,
        TRENDING_BUCKET_RETENTION_HOURS=1,
    )
    def test_run_applies_bucket_retention_cleanup(self):
        AttackerActivityBucket.objects.bulk_create(
            [
                AttackerActivityBucket(
                    attacker_ip="2.2.2.2",
                    feed_type="cowrie",
                    bucket_start=datetime(2026, 3, 20, 8, 0),
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
        TRENDING_PRECOMPUTE_WINDOWS_MINUTES=[60],
        TRENDING_PRECOMPUTE_LIMIT=10,
        TRENDING_BUCKET_RETENTION_HOURS=0,
    )
    def test_run_raises_on_invalid_retention_hours(self):
        with patch("greedybear.cronjobs.trending.timezone.now", return_value=datetime(2026, 3, 20, 10, 30, 0)):
            with self.assertRaises(ValueError):
                self.cron.run()
