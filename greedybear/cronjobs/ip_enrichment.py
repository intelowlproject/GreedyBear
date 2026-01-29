import logging
import os

import requests

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.repositories.ioc import IocRepository
from greedybear.cronjobs.repositories.ip_enrichment import TagRepository

logger = logging.getLogger(__name__)


class IPEnrichmentCron(Cronjob):
    """Enrich IPs with threat tags from public sources."""

    def __init__(
        self,
        tag_repo: TagRepository = None,
        ioc_repo: IocRepository = None,
    ):
        self.tag_repo = tag_repo or TagRepository()
        self.ioc_repo = ioc_repo or IocRepository()

    def run(self):
        """Fetch threat intelligence and enrich IPs with tags."""
        logger.info("Starting IP enrichment from public sources")

        # Backfill: Get ALL IOCs for enrichment
        iocs = self.ioc_repo.get_queryset()

        enriched_count = 0
        for ioc in iocs:
            try:
                # Check AbuseIPDB
                abuse_data = self._check_abuseipdb(ioc.name)
                if abuse_data and abuse_data.get("tags"):
                    self.tag_repo.create_tags(
                        ioc=ioc,
                        tags=abuse_data["tags"],
                        source="abuseipdb",
                    )
                    enriched_count += 1

                # Check Abuse.ch ThreatFox
                threat_data = self._check_abusech(ioc.name)
                if threat_data and threat_data.get("tags"):
                    self.tag_repo.create_tags(
                        ioc=ioc,
                        tags=threat_data["tags"],
                        source="abuse_ch",
                    )
                    enriched_count += 1

            except Exception as e:
                logger.error(f"Error enriching IP {ioc.name}: {e}")
                continue

        logger.info(f"Enriched {enriched_count} IOCs with tags")

    def _check_abuseipdb(self, ip_address: str) -> dict:
        """Check IP against AbuseIPDB."""
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if not api_key:
            logger.warning("AbuseIPDB API key not configured, skipping")
            return None

        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": api_key, "Accept": "application/json"}
            params = {"ipAddress": ip_address, "maxAgeInDays": 90}

            response = requests.get(url, headers=headers, params=params, timeout=10)
            response.raise_for_status()

            data = response.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)

            if score > 0:
                tags = []
                if score > 75:
                    tags.append("high-risk")
                if data.get("usageType"):
                    tags.append(data["usageType"].lower().replace(" ", "-"))

                return {"score": score, "tags": tags}

        except requests.RequestException as e:
            logger.error(f"AbuseIPDB API error for {ip_address}: {e}")

        return None

    def _check_abusech(self, ip_address: str) -> dict:
        """Check IP against Abuse.ch ThreatFox."""
        try:
            url = "https://threatfox-api.abuse.ch/api/v1/"
            data = {"query": "search_ioc", "search_term": ip_address}

            response = requests.post(url, json=data, timeout=10)
            response.raise_for_status()

            result = response.json()
            if result.get("query_status") == "ok":
                ioc_data = result.get("data", [])
                if ioc_data:
                    first_entry = ioc_data[0]
                    tags = first_entry.get("tags", [])
                    malware = first_entry.get("malware")
                    if malware and malware not in tags:
                        tags.append(malware)

                    return {
                        "tags": tags,
                        "confidence": first_entry.get("confidence_level", 0),
                    }

        except requests.RequestException as e:
            logger.error(f"Abuse.ch API error for {ip_address}: {e}")

        return None
