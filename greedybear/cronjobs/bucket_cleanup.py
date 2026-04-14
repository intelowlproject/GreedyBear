from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.repositories import TrendingBucketRepository

DEFAULT_TRENDING_MAX_WINDOW_MINUTES = (24 * 31 * 60) // 2
DEFAULT_TRENDING_BUCKET_RETENTION_HOURS = 24 * 31


class TrendingBucketCleanupCron(Cronjob):
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
            getattr(settings, "TRENDING_MAX_WINDOW_MINUTES", DEFAULT_TRENDING_MAX_WINDOW_MINUTES),
        )
        if max_window_minutes < 60:
            raise ValueError(f"TRENDING_MAX_WINDOW_MINUTES must be >= 60, got {max_window_minutes}")
        if max_window_minutes % 60:
            raise ValueError(f"TRENDING_MAX_WINDOW_MINUTES must be a multiple of 60, got {max_window_minutes}")

        retention_hours = self._positive_int_setting(
            "TRENDING_BUCKET_RETENTION_HOURS",
            getattr(settings, "TRENDING_BUCKET_RETENTION_HOURS", DEFAULT_TRENDING_BUCKET_RETENTION_HOURS),
        )

        retention_minutes = retention_hours * 60
        required_retention_minutes = 2 * max_window_minutes
        if retention_minutes < required_retention_minutes:
            raise ValueError(
                "TRENDING_BUCKET_RETENTION_HOURS must retain at least two windows "
                f"for TRENDING_MAX_WINDOW_MINUTES={max_window_minutes}: "
                f"required >= {required_retention_minutes} minutes, got {retention_minutes}"
            )

        return max_window_minutes, retention_hours

    def run(self) -> None:
        now = timezone.now().replace(minute=0, second=0, microsecond=0)
        _, retention_hours = self._validated_settings()
        cutoff = now - timedelta(hours=retention_hours)
        TrendingBucketRepository().delete_older_than(cutoff)
