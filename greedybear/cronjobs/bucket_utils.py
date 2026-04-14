import logging
from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import datetime
from ipaddress import ip_address
from typing import Any

from greedybear.cronjobs.extraction.utils import parse_timestamp
from greedybear.cronjobs.repositories import TrendingBucketRepository
from greedybear.utils import is_non_global_ip

logger = logging.getLogger(__name__)

BucketHit = Mapping[str, Any]
BucketKey = tuple[str, str, datetime]


def _bucket_start(timestamp: str) -> datetime:
    parsed = parse_timestamp(timestamp)
    return parsed.replace(minute=0, second=0, microsecond=0)


def _bucket_key_from_hit(hit: BucketHit) -> BucketKey | None:
    attacker_ip = hit.get("src_ip")
    feed_type = hit.get("type")
    timestamp = hit.get("@timestamp")
    if not attacker_ip or not feed_type or not timestamp:
        return None

    normalized_ip = str(attacker_ip)
    try:
        parsed_ip = ip_address(normalized_ip)
    except ValueError:
        return None

    if is_non_global_ip(parsed_ip):
        return None

    try:
        return normalized_ip, str(feed_type).lower(), _bucket_start(timestamp)
    except Exception:
        return None


def update_activity_buckets_from_hits(hits: Iterable[BucketHit]) -> int:
    counters: Counter[BucketKey] = Counter()
    for hit in hits:
        key = _bucket_key_from_hit(hit)
        if key is not None:
            counters[key] += 1

    if not counters:
        return 0

    try:
        return TrendingBucketRepository().upsert_bucket_counts(counters)
    except Exception as exc:
        logger.error("Failed to update activity buckets from hits for current chunk: %s", exc, exc_info=True)
        return 0
