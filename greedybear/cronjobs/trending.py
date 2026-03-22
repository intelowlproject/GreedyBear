from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import timedelta
from ipaddress import AddressValueError, ip_address
from typing import Any

from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import F, Sum
from django.utils import timezone

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.extraction.utils import parse_timestamp
from greedybear.models import AttackerActivityBucket, GeneralHoneypot, TrendingAttackerSnapshot
from greedybear.trending_utils import build_ranked_attackers


def _bucket_start(timestamp: str):
    parsed = parse_timestamp(timestamp)
    return parsed.replace(minute=0, second=0, microsecond=0)


def update_activity_buckets_from_hits(hits: Iterable[Mapping[str, Any]]) -> int:
    counters = Counter()
    for hit in hits:
        attacker_ip = hit.get("src_ip")
        feed_type = hit.get("type")
        timestamp = hit.get("@timestamp")
        if not attacker_ip or not feed_type or not timestamp:
            continue
        try:
            ip_address(attacker_ip)
        except AddressValueError:
            continue
        key = (attacker_ip, str(feed_type).lower(), _bucket_start(timestamp))
        counters[key] += 1

    created = []
    with transaction.atomic():
        for (attacker_ip, feed_type, bucket_start), interaction_count in counters.items():
            updated = AttackerActivityBucket.objects.filter(
                attacker_ip=attacker_ip,
                feed_type=feed_type,
                bucket_start=bucket_start,
            ).update(interaction_count=F("interaction_count") + interaction_count)
            if not updated:
                created.append(
                    AttackerActivityBucket(
                        attacker_ip=attacker_ip,
                        feed_type=feed_type,
                        bucket_start=bucket_start,
                        interaction_count=interaction_count,
                    )
                )
        if created:
            try:
                AttackerActivityBucket.objects.bulk_create(created)
            except IntegrityError:
                for row in created:
                    updated = AttackerActivityBucket.objects.filter(
                        attacker_ip=row.attacker_ip,
                        feed_type=row.feed_type,
                        bucket_start=row.bucket_start,
                    ).update(interaction_count=F("interaction_count") + row.interaction_count)
                    if not updated:
                        try:
                            AttackerActivityBucket.objects.create(
                                attacker_ip=row.attacker_ip,
                                feed_type=row.feed_type,
                                bucket_start=row.bucket_start,
                                interaction_count=row.interaction_count,
                            )
                        except IntegrityError:
                            AttackerActivityBucket.objects.filter(
                                attacker_ip=row.attacker_ip,
                                feed_type=row.feed_type,
                                bucket_start=row.bucket_start,
                            ).update(interaction_count=F("interaction_count") + row.interaction_count)

    return len(counters)


class TrendingAttackersCron(Cronjob):
    def run(self):
        now = timezone.now().replace(minute=0, second=0, microsecond=0)
        windows = getattr(settings, "TRENDING_PRECOMPUTE_WINDOWS_MINUTES", [24 * 60, 7 * 24 * 60])
        per_feed_limit = getattr(settings, "TRENDING_PRECOMPUTE_LIMIT", 500)
        retention_hours = getattr(settings, "TRENDING_BUCKET_RETENTION_HOURS", 24 * 31)

        feed_types = ["all"] + list(GeneralHoneypot.objects.filter(active=True).values_list("name", flat=True))
        normalized_feed_types = [feed_type.lower() for feed_type in feed_types]

        for window_minutes in windows:
            for feed_type in normalized_feed_types:
                snapshots = self._compute_snapshots(now, window_minutes, feed_type, per_feed_limit)
                with transaction.atomic():
                    TrendingAttackerSnapshot.objects.filter(window_minutes=window_minutes, feed_type=feed_type).delete()
                    if snapshots:
                        TrendingAttackerSnapshot.objects.bulk_create(snapshots)

        cutoff = now - timedelta(hours=retention_hours)
        AttackerActivityBucket.objects.filter(bucket_start__lt=cutoff).delete()

    def _compute_snapshots(self, now, window_minutes: int, feed_type: str, limit: int) -> list[TrendingAttackerSnapshot]:
        current_window_start = now - timedelta(minutes=window_minutes)
        previous_window_end = current_window_start
        previous_window_start = previous_window_end - timedelta(minutes=window_minutes)

        current_qs = AttackerActivityBucket.objects.filter(bucket_start__gte=current_window_start, bucket_start__lt=now)
        previous_qs = AttackerActivityBucket.objects.filter(bucket_start__gte=previous_window_start, bucket_start__lt=previous_window_end)

        if feed_type != "all":
            current_qs = current_qs.filter(feed_type=feed_type)
            previous_qs = previous_qs.filter(feed_type=feed_type)

        current_counts = dict(current_qs.values("attacker_ip").annotate(total=Sum("interaction_count")).values_list("attacker_ip", "total"))
        previous_counts = dict(previous_qs.values("attacker_ip").annotate(total=Sum("interaction_count")).values_list("attacker_ip", "total"))
        ranked_attackers = build_ranked_attackers(current_counts, previous_counts, limit)
        return [
            TrendingAttackerSnapshot(
                window_minutes=window_minutes,
                feed_type=feed_type,
                attacker_ip=row["attacker_ip"],
                current_interactions=row["current_interactions"],
                previous_interactions=row["previous_interactions"],
                interaction_delta=row["interaction_delta"],
                growth_score=row["growth_score"],
                current_rank=row["current_rank"],
                previous_rank=row["previous_rank"],
                rank_delta=row["rank_delta"],
            )
            for row in ranked_attackers
        ]
