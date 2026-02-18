from django.core.management.base import BaseCommand

from greedybear.cronjobs.enrichment.enrichment import enrich_ioc_with_tags
from greedybear.models import IOC


class Command(BaseCommand):
    help = "Backfill enrichment tags for existing IOCs from local ThreatFox and AbuseIPDB feeds"

    def add_arguments(self, parser):
        parser.add_argument(
            "--limit",
            type=int,
            default=None,
            help="Limit the number of IOCs to process (for testing)",
        )
        parser.add_argument(
            "--ioc-type",
            type=str,
            default="ip",
            choices=["ip", "domain", "all"],
            help="Type of IOCs to enrich (default: ip)",
        )

    def handle(self, *args, **options):
        limit = options.get("limit")
        ioc_type = options.get("ioc_type")

        # Build query
        queryset = IOC.objects.all()

        if ioc_type != "all":
            queryset = queryset.filter(type=ioc_type)

        if limit:
            queryset = queryset[:limit]

        total_iocs = queryset.count()
        self.stdout.write(f"Starting backfill for {total_iocs} IOCs...")

        enriched_count = 0
        error_count = 0

        for idx, ioc in enumerate(queryset, 1):
            try:
                # Check if IOC already has tags
                existing_tags = ioc.tags.count()

                # Enrich the IOC
                enrich_ioc_with_tags(ioc)

                # Count new tags
                new_tags = ioc.tags.count()
                if new_tags > existing_tags:
                    enriched_count += 1
                    self.stdout.write(f"[{idx}/{total_iocs}] Enriched {ioc.name} with {new_tags - existing_tags} new tags (total: {new_tags})")
                else:
                    self.stdout.write(f"[{idx}/{total_iocs}] No new tags for {ioc.name}")

            except Exception as e:
                error_count += 1
                self.stdout.write(self.style.ERROR(f"[{idx}/{total_iocs}] Error enriching {ioc.name}: {e}"))

        self.stdout.write(self.style.SUCCESS(f"\nBackfill complete! Enriched {enriched_count}/{total_iocs} IOCs. Errors: {error_count}"))
