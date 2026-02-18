from django.core.management.base import BaseCommand

from greedybear.cronjobs.enrichment.enrichment import enrich_iocs
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

        # Process in batches
        batch_size = 1000
        for start_idx in range(0, total_iocs, batch_size):
            end_idx = start_idx + batch_size
            batch_iocs = list(queryset[start_idx:end_idx])

            try:
                self.stdout.write(f"Processing batch {start_idx}-{min(end_idx, total_iocs)}/{total_iocs}...")
                enrich_iocs(batch_iocs)
                enriched_count += len(batch_iocs)
            except Exception as e:
                error_count += 1
                self.stdout.write(self.style.ERROR(f"Error processing batch starting at {start_idx}: {e}"))

        self.stdout.write(self.style.SUCCESS(f"\nBackfill complete! Processed {enriched_count}/{total_iocs} IOCs in batches. Batch Errors: {error_count}"))
