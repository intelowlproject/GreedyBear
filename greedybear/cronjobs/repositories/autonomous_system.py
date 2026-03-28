import logging

from greedybear.models import AutonomousSystem


class ASRepository:
    """Repository to handle AutonomousSystem objects with caching."""

    def __init__(self, preload_cache: bool = True):
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._cache = {}
        if preload_cache:
            self._cache = {as_obj.asn: as_obj for as_obj in AutonomousSystem.objects.all()}
            self.log.info(f"Preloaded {len(self._cache)} ASs into cache")

    def get_or_create(self, asn: int, name: str) -> AutonomousSystem:
        """
        Get or create an AutonomousSystem by ASN with in-memory cache.

        If AS exists but name is missing and a new name is provided, update it.

        Args:
            asn: Autonomous System Number
            name: Name of the AS

        Returns:
            AutonomousSystem instance
        """
        if asn in self._cache:
            return self._cache[asn]

        as_obj, created = AutonomousSystem.objects.get_or_create(asn=asn, defaults={"name": name or ""})

        if created:
            self.log.info(f"Created new AS {asn} with name '{name}'")
        elif not as_obj.name and name:
            as_obj.name = name
            as_obj.save(update_fields=["name"])
            self.log.info(f"Updated AS {asn} name to '{name}'")

        self._cache[asn] = as_obj
        return as_obj
