import logging
from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.utils import timezone

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.extraction.utils import parse_timestamp
from greedybear.cronjobs.repositories import TrendingBucketRepository
from greedybear.utils import is_ip_address

logger = logging.getLogger(__name__)


def _rank_map(sorted_counts: list[tuple[str, int]]) -> dict[str, int]:
    return {attacker_ip: rank for rank, (attacker_ip, _) in enumerate(sorted_counts, start=1)}


def growth_score(current_count: int, previous_count: int) -> float:
    if previous_count == 0:
        return round(float(current_count), 4)
    return round((current_count - previous_count) / previous_count, 4)


def rank_delta(current_rank: int | None, previous_rank: int | None) -> int | None:
    if current_rank is not None and previous_rank is not None:
        return previous_rank - current_rank
    if current_rank is None and previous_rank is not None:
        return -previous_rank
    return None


def attacker_sort_tuple(attacker_ip: str, current_rank: int | None, current_count: int, previous_count: int):
    return (current_rank is None, current_rank or 10**9, -(current_count - previous_count), -previous_count, attacker_ip)


def build_ranked_attackers(current_counts: Mapping[str, int], previous_counts: Mapping[str, int], limit: int) -> list[dict]:
    sorted_current = sorted(current_counts.items(), key=lambda item: (-item[1], item[0]))
    sorted_previous = sorted(previous_counts.items(), key=lambda item: (-item[1], item[0]))

    current_ranks = _rank_map(sorted_current)
    previous_ranks = _rank_map(sorted_previous)

    candidate_ips = {ip for ip, _ in sorted_current[:limit]}
    candidate_ips |= {ip for ip, _ in sorted_previous[:limit]}

    sorted_ips = sorted(
        candidate_ips,
        key=lambda attacker_ip: attacker_sort_tuple(
            attacker_ip,
            current_ranks.get(attacker_ip),
            current_counts.get(attacker_ip, 0),
            previous_counts.get(attacker_ip, 0),
        ),
    )[:limit]

    attackers = []
    for attacker_ip in sorted_ips:
        current_rank = current_ranks.get(attacker_ip)
        previous_rank = previous_ranks.get(attacker_ip)
        current_count = current_counts.get(attacker_ip, 0)
        previous_count = previous_counts.get(attacker_ip, 0)

        attackers.append(
            {
                "attacker_ip": attacker_ip,
                "current_interactions": current_count,
                "previous_interactions": previous_count,
                "interaction_delta": current_count - previous_count,
                "growth_score": growth_score(current_count, previous_count),
                "current_rank": current_rank,
                "previous_rank": previous_rank,
                "rank_delta": rank_delta(current_rank, previous_rank),
            }
        )

    return attackers


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

    try:
        return TrendingBucketRepository().upsert_bucket_counts(counters)
    except Exception as exc:
        logger.error("Failed to update activity buckets from hits for current chunk: %s", exc, exc_info=True)
        return 0


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

    def _validated_settings(self) -> tuple[int, int]:
        max_window_minutes = self._positive_int_setting(
            "TRENDING_MAX_WINDOW_MINUTES",
            getattr(settings, "TRENDING_MAX_WINDOW_MINUTES", (24 * 31 * 60) // 2),
        )
        if max_window_minutes < 60:
            raise ValueError(f"TRENDING_MAX_WINDOW_MINUTES must be >= 60, got {max_window_minutes}")
        if max_window_minutes % 60:
            raise ValueError(f"TRENDING_MAX_WINDOW_MINUTES must be a multiple of 60, got {max_window_minutes}")

        retention_hours = self._positive_int_setting("TRENDING_BUCKET_RETENTION_HOURS", getattr(settings, "TRENDING_BUCKET_RETENTION_HOURS", 24 * 31))

        max_allowed_window_minutes = max(60, (retention_hours * 60) // 2)
        if max_window_minutes > max_allowed_window_minutes:
            raise ValueError(
                "TRENDING_MAX_WINDOW_MINUTES cannot exceed half of retention horizon "
                f"({max_allowed_window_minutes} minutes based on TRENDING_BUCKET_RETENTION_HOURS), "
                f"got {max_window_minutes}"
            )

        return max_window_minutes, retention_hours

    def run(self):
        now = timezone.now().replace(minute=0, second=0, microsecond=0)
        _, retention_hours = self._validated_settings()
        bucket_repo = TrendingBucketRepository()

        cutoff = now - timedelta(hours=retention_hours)
        bucket_repo.delete_older_than(cutoff)
