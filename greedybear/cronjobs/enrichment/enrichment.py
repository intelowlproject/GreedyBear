"""
Enrichment utilities for adding tags to IOCs from local feeds.
"""

import logging
from collections import defaultdict

from django.db import transaction

from greedybear.models import IOC, AbuseIPDBFeed, Tag, ThreatFoxFeed

logger = logging.getLogger(__name__)


def enrich_iocs(iocs: list[IOC]) -> None:
    """
    Enrich a list of IOCs with tags from local ThreatFox and AbuseIPDB feeds.

    This function checks if the IOCs' IPs exist in the local ThreatFox and
    AbuseIPDB tables, and if found, creates tags with relevant metadata.
    Optimized for bulk processing to minimize database queries.

    Args:
        iocs: List of IOC instances to enrich (must be saved to database).
              Only IOCs of type 'ip' will be processed.
    """
    # Filter valid saved IP IOCs
    valid_iocs = [ioc for ioc in iocs if ioc.id and ioc.type == "ip"]
    if not valid_iocs:
        return

    logger.info(f"Enriching {len(valid_iocs)} IOCs")

    ioc_map = {ioc.name: ioc for ioc in valid_iocs}
    ips = list(ioc_map.keys())

    # Bulk fetch ThreatFox data
    threatfox_feeds = ThreatFoxFeed.objects.filter(ip_address__in=ips)
    threatfox_map = defaultdict(list)
    for feed in threatfox_feeds:
        threatfox_map[feed.ip_address].append(feed)

    # Bulk fetch AbuseIPDB data
    abuseipdb_feeds = AbuseIPDBFeed.objects.filter(ip_address__in=ips)
    abuseipdb_map = {feed.ip_address: feed for feed in abuseipdb_feeds}

    tags_to_create = []

    # Use a transaction to ensure atomic updates and lock the IOC rows to prevent race conditions
    with transaction.atomic():
        # Lock the IOC rows. This ensures that no other process can modify these IOCs
        # or their related tags while we are working on them.
        # We must evaluate the queryset (e.g., list()) to actually acquire the lock.
        list(IOC.objects.filter(id__in=[ioc.id for ioc in valid_iocs]).select_for_update())

        # --- ThreatFox Enrichment ---
        # Delete existing ThreatFox tags for these IOCs before enriching (allows re-enrichment)
        Tag.objects.filter(ioc__in=valid_iocs, source="threatfox").delete()

        for ip, feeds in threatfox_map.items():
            ioc = ioc_map.get(ip)
            if not ioc:
                continue

            for entry in feeds:
                # Add malware tag
                if entry.malware_printable or entry.malware:
                    tags_to_create.append(
                        Tag(
                            ioc=ioc,
                            key="malware",
                            value=entry.malware_printable or entry.malware,
                            source="threatfox",
                        )
                    )

                # Add threat type tag
                if entry.threat_type:
                    tags_to_create.append(
                        Tag(
                            ioc=ioc,
                            key="threat_type",
                            value=entry.threat_type,
                            source="threatfox",
                        )
                    )

                # Add confidence level tag
                if entry.confidence_level is not None:
                    tags_to_create.append(
                        Tag(
                            ioc=ioc,
                            key="confidence_level",
                            value=str(entry.confidence_level),
                            source="threatfox",
                        )
                    )

                # Add individual tags from ThreatFox
                if entry.tags:
                    for tag_value in entry.tags:
                        if tag_value:
                            tags_to_create.append(
                                Tag(
                                    ioc=ioc,
                                    key="tag",
                                    value=tag_value,
                                    source="threatfox",
                                )
                            )

        # --- AbuseIPDB Enrichment ---
        # Delete existing AbuseIPDB tags for these IOCs
        Tag.objects.filter(ioc__in=valid_iocs, source="abuseipdb").delete()

        for ip, entry in abuseipdb_map.items():
            ioc = ioc_map.get(ip)
            if not ioc:
                continue

            # Add abuse confidence score
            if entry.abuse_confidence_score is not None:
                tags_to_create.append(
                    Tag(
                        ioc=ioc,
                        key="confidence_of_abuse",
                        value=f"{entry.abuse_confidence_score}%",
                        source="abuseipdb",
                    )
                )

            # Add usage type
            if entry.usage_type:
                tags_to_create.append(
                    Tag(
                        ioc=ioc,
                        key="usage_type",
                        value=entry.usage_type,
                        source="abuseipdb",
                    )
                )

            # Add country code
            if entry.country_code:
                tags_to_create.append(
                    Tag(
                        ioc=ioc,
                        key="country",
                        value=entry.country_code,
                        source="abuseipdb",
                    )
                )

        # Bulk create all tags
        if tags_to_create:
            Tag.objects.bulk_create(tags_to_create)
            logger.info(f"Created {len(tags_to_create)} enrichment tags")


def enrich_ioc_with_tags(ioc: IOC) -> None:
    """
    Wrapper for single IOC enrichment (backward compatibility implementation).
    Use enrich_iocs for bulk processing where possible.
    """
    enrich_iocs([ioc])
