"""
Enrichment utilities for adding tags to IOCs from local feeds.
"""

import logging

from greedybear.cronjobs.repositories import AbuseIPDBRepository, TagRepository, ThreatFoxRepository
from greedybear.models import IOC

logger = logging.getLogger(__name__)


def enrich_ioc_with_tags(ioc: IOC) -> None:
    """
    Enrich an IOC with tags from local ThreatFox and AbuseIPDB feeds.

    This function checks if the IOC's IP exists in the local ThreatFox and
    AbuseIPDB tables, and if found, creates tags with relevant metadata.

    Args:
        ioc: IOC instance to enrich (must be saved to database).
    """
    if not ioc.id:
        logger.warning(f"Cannot enrich unsaved IOC: {ioc.name}")
        return

    # Only enrich IP addresses
    if ioc.type != "ip":
        return

    tag_repo = TagRepository()
    threatfox_repo = ThreatFoxRepository()
    abuseipdb_repo = AbuseIPDBRepository()

    # Enrich from ThreatFox feed
    threatfox_entries = threatfox_repo.get_by_ip(ioc.name)
    for entry in threatfox_entries:
        # Add malware tag
        if entry.malware_printable or entry.malware:
            tag_repo.create_tag(
                ioc=ioc,
                key="malware",
                value=entry.malware_printable or entry.malware,
                source="threatfox",
            )

        # Add threat type tag
        if entry.threat_type:
            tag_repo.create_tag(
                ioc=ioc,
                key="threat_type",
                value=entry.threat_type,
                source="threatfox",
            )

        # Add confidence level tag
        if entry.confidence_level is not None:
            tag_repo.create_tag(
                ioc=ioc,
                key="confidence_level",
                value=str(entry.confidence_level),
                source="threatfox",
            )

        # Add individual tags from ThreatFox
        for tag_value in entry.tags:
            if tag_value:
                tag_repo.create_tag(
                    ioc=ioc,
                    key="tag",
                    value=tag_value,
                    source="threatfox",
                )

    if threatfox_entries:
        logger.info(f"Enriched IOC {ioc.name} with {len(threatfox_entries)} ThreatFox entries")

    # Enrich from AbuseIPDB feed
    abuseipdb_entry = abuseipdb_repo.get_by_ip(ioc.name)
    if abuseipdb_entry:
        # Add abuse confidence score
        if abuseipdb_entry.abuse_confidence_score is not None:
            tag_repo.create_tag(
                ioc=ioc,
                key="confidence_of_abuse",
                value=f"{abuseipdb_entry.abuse_confidence_score}%",
                source="abuseipdb",
            )

        # Add usage type
        if abuseipdb_entry.usage_type:
            tag_repo.create_tag(
                ioc=ioc,
                key="usage_type",
                value=abuseipdb_entry.usage_type,
                source="abuseipdb",
            )

        # Add country code
        if abuseipdb_entry.country_code:
            tag_repo.create_tag(
                ioc=ioc,
                key="country",
                value=abuseipdb_entry.country_code,
                source="abuseipdb",
            )

        logger.info(f"Enriched IOC {ioc.name} with AbuseIPDB data")
