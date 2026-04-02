import logging
from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.db import connection, transaction
from django.db.models import Sum
from django.utils import timezone

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.extraction.utils import parse_timestamp
from greedybear.models import AttackerActivityBucket, Honeypot, TrendingAttackerSnapshot
from greedybear.trending_utils import build_ranked_attackers
from greedybear.utils import is_ip_address


logger = logging.getLogger(__name__)


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
        if not is_ip_address(str(attacker_ip)):
            continue
        try:
            key = (str(attacker_ip), str(feed_type).lower(), _bucket_start(timestamp))
        except Exception:
            continue
        counters[key] += 1

    if not counters:
        return 0

    table_name = AttackerActivityBucket._meta.db_table
    quoted_table_name = connection.ops.quote_name(table_name)
    values_sql = ",".join(["(%s, %s, %s, %s)"] * len(counters))
    params = []
    for (attacker_ip, feed_type, bucket_start), interaction_count in counters.items():
        params.extend([attacker_ip, feed_type, bucket_start, interaction_count])

    query = f"""
        INSERT INTO {quoted_table_name} (attacker_ip, feed_type, bucket_start, interaction_count)
        VALUES {values_sql}
        ON CONFLICT (attacker_ip, feed_type, bucket_start)
        DO UPDATE
        SET interaction_count = {quoted_table_name}.interaction_count + EXCLUDED.interaction_count
    """
    try:
        with connection.cursor() as cursor:
            cursor.execute(query, params)
    except Exception as exc:
        logger.error("Failed to update activity buckets from hits for current chunk: %s", exc, exc_info=True)
        return 0

    return len(counters)


class TrendingAttackersCron(Cronjob):
    @staticmethod
    def _positive_int_setting(name: str, value) -> int:
        try:
            parsed_value = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} must be a positive integer, got {value!r}") from exc

        if parsed_value < 1:
            raise ValueError(f"{name} must be >= 1, got {parsed_value}")

        return parsed_value

    def run(self):
        now = timezone.now().replace(minute=0, second=0, microsecond=0)
        windows = getattr(settings, "TRENDING_PRECOMPUTE_WINDOWS_MINUTES", [24 * 60, 7 * 24 * 60])
        if not windows:
            raise ValueError("TRENDING_PRECOMPUTE_WINDOWS_MINUTES must contain at least one value")
        validated_windows = []
        for window_minutes in windows:
            parsed_window = self._positive_int_setting("TRENDING_PRECOMPUTE_WINDOWS_MINUTES entries", window_minutes)
            if parsed_window % 60:
                raise ValueError(f"TRENDING_PRECOMPUTE_WINDOWS_MINUTES entries must be multiples of 60, got {parsed_window}")
            validated_windows.append(parsed_window)

        per_feed_limit = self._positive_int_setting("TRENDING_PRECOMPUTE_LIMIT", getattr(settings, "TRENDING_PRECOMPUTE_LIMIT", 500))
        retention_hours = self._positive_int_setting("TRENDING_BUCKET_RETENTION_HOURS", getattr(settings, "TRENDING_BUCKET_RETENTION_HOURS", 24 * 31))

        feed_types = ["all"] + list(Honeypot.objects.filter(active=True).values_list("name", flat=True))
        normalized_feed_types = [feed_type.lower() for feed_type in feed_types]

        for window_minutes in validated_windows:
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
