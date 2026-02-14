import logging
from datetime import datetime, timedelta

from greedybear.models import FireHolList


class FireHolRepository:
    """
    Repository for data access to FireHol blocklist entries.
    """

    def __init__(self):
        """Initialize the repository."""
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def get_or_create(self, ip_address: str, source: str) -> tuple[FireHolList, bool]:
        """
        Get an existing FireHol entry or create a new one.

        Args:
            ip_address: IP address or CIDR block.
            source: Source name (e.g., 'blocklist_de', 'greensnow').

        Returns:
            Tuple of (FireHolList object, created_flag) where created_flag is True if new.
        """
        entry, created = FireHolList.objects.get_or_create(
            ip_address=ip_address, source=source
        )
        return entry, created

    def save(self, entry: FireHolList) -> FireHolList:
        """
        Save a FireHolList entry to the database.

        Args:
            entry: FireHolList instance to save.

        Returns:
            The saved FireHolList instance.
        """
        entry.save()
        return entry

    def delete_old_entries(self, cutoff_date: datetime) -> int:
        """
        Delete FireHolList entries older than the specified date.

        Args:
            cutoff_date: DateTime threshold - entries added before this will be deleted.

        Returns:
            Number of entries deleted.
        """
        deleted_count, _ = FireHolList.objects.filter(added__lt=cutoff_date).delete()
        return deleted_count

    def cleanup_old_entries(self, days: int = 30) -> int:
        """
        Delete FireHolList entries older than the specified number of days.

        Args:
            days: Number of days to retain entries. Defaults to 30.

        Returns:
            Number of entries deleted.
        """
        cutoff_date = datetime.now() - timedelta(days=days)
        return self.delete_old_entries(cutoff_date)
