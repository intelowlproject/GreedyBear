import logging

from django.db.models import Count, Max, Min, Sum
from django.db.models.functions import Coalesce

from greedybear.models import IOC, AutonomousSystem


class ASRepository:
    """Repository to handle AutonomousSystem objects with caching."""

    AGGREGATE_FIELDS = [
        "ioc_count",
        "total_attack_count",
        "total_interaction_count",
        "total_login_attempts",
        "expected_ioc_count",
        "expected_interactions",
        "first_seen",
        "last_seen",
    ]

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

    def refresh_aggregates(self) -> int:
        """
        Recompute and bulk-update pre-calculated aggregate fields on every
        AutonomousSystem record.

        Performs a single GROUP BY query on the IOC table to compute the metrics,
        then applies updates via bulk_update.  ASNs that no longer own any IOCs
        are reset to their default (zero / null) values.

        Returns:
            Number of AutonomousSystem records updated.
        """
        # Single GROUP BY query — one pass over the IOC table.
        agg_rows = (
            IOC.objects.exclude(autonomous_system__isnull=True)
            .values("autonomous_system__asn")
            .annotate(
                ioc_count=Count("id"),
                total_attack_count=Coalesce(Sum("attack_count"), 0),
                total_interaction_count=Coalesce(Sum("interaction_count"), 0),
                total_login_attempts=Coalesce(Sum("login_attempts"), 0),
                expected_ioc_count=Coalesce(Sum("recurrence_probability"), 0.0),
                expected_interactions=Coalesce(Sum("expected_interactions"), 0.0),
                first_seen=Min("first_seen"),
                last_seen=Max("last_seen"),
            )
        )

        agg_by_asn = {row["autonomous_system__asn"]: row for row in agg_rows}

        # Fetch all AS objects once
        all_as_objects = list(AutonomousSystem.objects.all())
        to_update = []

        for as_obj in all_as_objects:
            row = agg_by_asn.get(as_obj.asn)
            if row:
                as_obj.ioc_count = row["ioc_count"]
                as_obj.total_attack_count = row["total_attack_count"]
                as_obj.total_interaction_count = row["total_interaction_count"]
                as_obj.total_login_attempts = row["total_login_attempts"]
                as_obj.expected_ioc_count = row["expected_ioc_count"]
                as_obj.expected_interactions = row["expected_interactions"]
                as_obj.first_seen = row["first_seen"]
                as_obj.last_seen = row["last_seen"]
            else:
                # ASN no longer has any IOCs — reset to defaults
                as_obj.ioc_count = 0
                as_obj.total_attack_count = 0
                as_obj.total_interaction_count = 0
                as_obj.total_login_attempts = 0
                as_obj.expected_ioc_count = 0.0
                as_obj.expected_interactions = 0.0
                as_obj.first_seen = None
                as_obj.last_seen = None
            to_update.append(as_obj)

        if to_update:
            AutonomousSystem.objects.bulk_update(to_update, self.AGGREGATE_FIELDS, batch_size=500)

        # Rebuild in-memory cache so it reflects the refreshed aggregate values.
        self._cache = {as_obj.asn: as_obj for as_obj in all_as_objects}

        self.log.info(f"Refreshed aggregates for {len(to_update)} ASs ({len(agg_by_asn)} with IOCs)")
        return len(to_update)
