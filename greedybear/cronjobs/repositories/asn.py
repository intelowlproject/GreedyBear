import logging

from greedybear.models import AutonomousSystem


class ASNRepository:
    """Repository to handle AutonomousSystem objects."""

    def __init__(self):
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._cache = {}

    def get_or_create(self, asn: int, name: str) -> AutonomousSystem:
        """
        Get or create an AutonomousSystem by ASN with in-memory cache.
        If AS exists but name is missing and a new name is provided, update it.

        Args:
            asn: Autonomous System Number
            name: AS organization name

        Returns:
            AutonomousSystem instance
        """
        if asn in self._cache:
            return self._cache[asn]

        as_obj, created = AutonomousSystem.objects.get_or_create(asn=asn, defaults={"name": name or ""})

        if created:
            self.log.info(f"Created new ASN {asn} with name '{name or ''}'")
        elif name and not as_obj.name:
            as_obj.name = name
            as_obj.save(update_fields=["name"])
            self.log.info(f"Updated ASN {asn} name to '{name}'")

        self._cache[asn] = as_obj
        return as_obj
