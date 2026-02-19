import logging
from datetime import datetime, timedelta

from greedybear.models import AbuseIPDBFeed


class AbuseIPDBRepository:
    """Repository for data access to AbuseIPDB feed entries."""

    def __init__(self):
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def get_or_create(
        self,
        ip_address: str,
        abuse_confidence_score: int = None,
        usage_type: str = "",
        country_code: str = "",
    ) -> tuple[AbuseIPDBFeed, bool]:
        """
        Get an existing AbuseIPDB entry or create a new one.

        Args:
            ip_address: IP address from AbuseIPDB.
            abuse_confidence_score: Confidence score (0-100).
            usage_type: Usage type of the IP.
            country_code: Country code.

        Returns:
            Tuple of (AbuseIPDBFeed object, created_flag) where created_flag is True if new.
        """
        entry, created = AbuseIPDBFeed.objects.get_or_create(
            ip_address=ip_address,
            defaults={
                "abuse_confidence_score": abuse_confidence_score,
                "usage_type": usage_type,
                "country_code": country_code,
            },
        )

        # Update if entry exists but has different data
        if not created:
            updated = False
            if abuse_confidence_score is not None and entry.abuse_confidence_score != abuse_confidence_score:
                entry.abuse_confidence_score = abuse_confidence_score
                updated = True
            if usage_type and entry.usage_type != usage_type:
                entry.usage_type = usage_type
                updated = True
            if country_code and entry.country_code != country_code:
                entry.country_code = country_code
                updated = True
            if updated:
                entry.added = datetime.now()
                entry.save()
                self.log.debug(f"Updated AbuseIPDB entry for {ip_address}")

        return entry, created

    def get_by_ip(self, ip_address: str) -> AbuseIPDBFeed | None:
        """
        Get AbuseIPDB entry for a specific IP address.

        Args:
            ip_address: IP address to look up.

        Returns:
            AbuseIPDBFeed object or None if not found.
        """
        try:
            return AbuseIPDBFeed.objects.get(ip_address=ip_address)
        except AbuseIPDBFeed.DoesNotExist:
            return None

    def clear_all(self) -> int:
        """
        Delete all AbuseIPDB feed entries.

        Returns:
            Number of entries deleted.
        """
        count, _ = AbuseIPDBFeed.objects.all().delete()
        self.log.info(f"Cleared all AbuseIPDB feed entries ({count} total)")
        return count

    def cleanup_old_entries(self, days: int = 30) -> int:
        """
        Delete AbuseIPDB entries older than specified days.

        Args:
            days: Number of days to keep entries.

        Returns:
            Number of entries deleted.
        """
        cutoff_date = datetime.now() - timedelta(days=days)
        count, _ = AbuseIPDBFeed.objects.filter(added__lt=cutoff_date).delete()
        self.log.info(f"Deleted {count} AbuseIPDB entries older than {days} days")
        return count

    def count(self) -> int:
        """
        Get the count of AbuseIPDB entries.

        Returns:
            Number of entries in the database.
        """
        return AbuseIPDBFeed.objects.count()

    def enforce_limit(self, max_entries: int = 10000) -> int:
        """
        Enforce the maximum number of AbuseIPDB entries (keep most recent).

        Args:
            max_entries: Maximum number of entries to keep (default 10k).

        Returns:
            Number of entries deleted.
        """
        current_count = self.count()
        if current_count <= max_entries:
            return 0

        self.log.info(f"Enforced limit of {max_entries} entries")

        # Delete oldest entries beyond the limit
        entries_to_delete = current_count - max_entries
        old_entries = AbuseIPDBFeed.objects.order_by("added")[:entries_to_delete]
        old_entry_ids = list(old_entries.values_list("id", flat=True))

        count, _ = AbuseIPDBFeed.objects.filter(id__in=old_entry_ids).delete()

        self.log.info(f"Deleted {count} oldest entries")
        return count
