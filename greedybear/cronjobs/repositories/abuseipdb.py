import logging

from greedybear.models import AbuseIPDBEntry


class AbuseIPDBRepository:
    """Repository for data access to AbuseIPDB blacklist entries."""

    def __init__(self):
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def get_or_create(self, ip_address: str, abuse_confidence_score: int = 0, last_reported_at=None) -> tuple[AbuseIPDBEntry, bool]:
        defaults = {"abuse_confidence_score": abuse_confidence_score}
        if last_reported_at:
            defaults["last_reported_at"] = last_reported_at

        entry, created = AbuseIPDBEntry.objects.get_or_create(ip_address=ip_address, defaults=defaults)

        # Update if exists and data changed
        if not created:
            updated = False
            if entry.abuse_confidence_score != abuse_confidence_score:
                entry.abuse_confidence_score = abuse_confidence_score
                updated = True
            if last_reported_at and entry.last_reported_at != last_reported_at:
                entry.last_reported_at = last_reported_at
                updated = True
            if updated:
                entry.save()

        return entry, created

    def count(self) -> int:
        return AbuseIPDBEntry.objects.count()

    def delete_all(self):
        AbuseIPDBEntry.objects.all().delete()
