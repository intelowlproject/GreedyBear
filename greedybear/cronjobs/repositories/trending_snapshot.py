from django.db import transaction

from greedybear.models import TrendingAttackerSnapshot


class TrendingSnapshotRepository:
    def replace_snapshots(self, window_minutes: int, feed_type: str, snapshots: list[TrendingAttackerSnapshot]) -> None:
        with transaction.atomic():
            TrendingAttackerSnapshot.objects.filter(window_minutes=window_minutes, feed_type=feed_type).delete()
            if snapshots:
                TrendingAttackerSnapshot.objects.bulk_create(snapshots)
