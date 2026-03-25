import logging

from greedybear.models import AutonomousSystem


class ASRepository:
    """Repository to handle AutonomousSystem objects with caching."""

    def __init__(self):
        self.log = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    @property
    def cache(self) -> dict[int, AutonomousSystem]:
        """
        Lazy-loaded cache of AS objects by ASN.
        Fetched on first access to avoid DB queries during __init__.
        """
        if not hasattr(self, "_cache"):
            self.log.debug("Preloading ASs into cache from database")
            self._cache = {as_obj.asn: as_obj for as_obj in AutonomousSystem.objects.all()}
            self.log.info(f"Preloaded {len(self._cache)} ASs into cache")
        return self._cache

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
        if asn in self.cache:
            as_obj = self.cache[asn]
            if not as_obj.name and name:
                as_obj.name = name
                as_obj.save(update_fields=["name"])
                self.log.info(f"Updated AS {asn} name to '{name}'")
            return as_obj

        as_obj, created = AutonomousSystem.objects.get_or_create(asn=asn, defaults={"name": name or ""})

        if created:
            self.log.info(f"Created new AS {asn} with name '{name}'")
        elif not as_obj.name and name:
            as_obj.name = name
            as_obj.save(update_fields=["name"])
            self.log.info(f"Updated AS {asn} name to '{name}'")

        self.cache[asn] = as_obj
        return as_obj
