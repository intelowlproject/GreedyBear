import logging
from datetime import datetime, timedelta

from greedybear.models import ThreatFoxFeed


class ThreatFoxRepository:
    """Repository for data access to ThreatFox feed entries."""

    def __init__(self):
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def get_or_create(
        self,
        ip_address: str,
        malware: str = "",
        malware_printable: str = "",
        threat_type: str = "",
        confidence_level: int = None,
        tags: list = None,
    ) -> tuple[ThreatFoxFeed, bool]:
        """
        Get an existing ThreatFox entry or create a new one.

        Args:
            ip_address: IP address from ThreatFox.
            malware: Malware family name.
            malware_printable: Human-readable malware name.
            threat_type: Type of threat.
            confidence_level: Confidence level (0-100).
            tags: List of tags.

        Returns:
            Tuple of (ThreatFoxFeed object, created_flag) where created_flag is True if new.
        """
        if tags is None:
            tags = []

        entry, created = ThreatFoxFeed.objects.get_or_create(
            ip_address=ip_address,
            malware=malware,
            defaults={
                "malware_printable": malware_printable,
                "threat_type": threat_type,
                "confidence_level": confidence_level,
                "tags": tags,
            },
        )
        return entry, created

    def get_by_ip(self, ip_address: str) -> list[ThreatFoxFeed]:
        """
        Get all ThreatFox entries for a specific IP address.

        Args:
            ip_address: IP address to look up.

        Returns:
            List of ThreatFoxFeed objects.
        """
        return list(ThreatFoxFeed.objects.filter(ip_address=ip_address))

    def clear_all(self) -> int:
        """
        Delete all ThreatFox feed entries.

        Returns:
            Number of entries deleted.
        """
        count, _ = ThreatFoxFeed.objects.all().delete()
        self.log.info(f"Cleared all ThreatFox feed entries ({count} total)")
        return count

    def cleanup_old_entries(self, days: int = 30) -> int:
        """
        Delete ThreatFox entries older than specified days.

        Args:
            days: Number of days to keep entries.

        Returns:
            Number of entries deleted.
        """
        cutoff_date = datetime.now() - timedelta(days=days)
        count, _ = ThreatFoxFeed.objects.filter(added__lt=cutoff_date).delete()
        self.log.info(f"Deleted {count} ThreatFox entries older than {days} days")
        return count

    def count(self) -> int:
        """
        Get the count of ThreatFox entries.

        Returns:
            Number of entries in the database.
        """
        return ThreatFoxFeed.objects.count()
