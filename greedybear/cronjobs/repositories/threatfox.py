import logging

from greedybear.models import ThreatFoxEntry


class ThreatFoxRepository:
    """Repository for data access to ThreatFox entries."""

    def __init__(self):
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def get_or_create(self, ip_address: str, malware_family: str = "", last_seen_online=None) -> tuple[ThreatFoxEntry, bool]:
        defaults = {"malware_family": malware_family}
        if last_seen_online:
            defaults["last_seen_online"] = last_seen_online

        entry, created = ThreatFoxEntry.objects.get_or_create(ip_address=ip_address, defaults=defaults)

        # Update if exists and data changed
        if not created:
            updated = False
            if malware_family and entry.malware_family != malware_family:
                entry.malware_family = malware_family
                updated = True
            if last_seen_online and entry.last_seen_online != last_seen_online:
                entry.last_seen_online = last_seen_online
                updated = True
            if updated:
                entry.save()

        return entry, created

    def count(self) -> int:
        return ThreatFoxEntry.objects.count()

    def delete_all(self):
        ThreatFoxEntry.objects.all().delete()
