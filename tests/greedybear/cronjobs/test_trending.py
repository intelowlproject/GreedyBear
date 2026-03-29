from datetime import datetime

from greedybear.cronjobs.trending import update_activity_buckets_from_hits
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
