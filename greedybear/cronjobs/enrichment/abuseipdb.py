import requests
from django.conf import settings

from greedybear.cronjobs.enrichment import ProtoTag, TagEnrichment
from greedybear.cronjobs.extraction.utils import is_valid_ipv4


class AbuseIpdbEnrichment(TagEnrichment):
    SOURCE_NAME = "abuseipdb"
    API_KEY = settings.ABUSEIPDB_API_KEY
    MAX_ENTRIES = 10000  # Hard limit as per free API tier

    def _fetch_feed(self) -> list[dict]:
        # Fetch blocklist from AbuseIPDB
        url = "https://api.abuseipdb.com/api/v2/blacklist"
        headers = {"Key": self.API_KEY, "Accept": "application/json"}
        params = {
            "confidenceMinimum": 75,  # Only IPs with confidence >= 75%
            "limit": self.MAX_ENTRIES,  # Maximum 10k entries
        }

        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()

        json_data = response.json()
        return json_data.get("data", [])


    def _parse_tags(self, raw_data: list[dict]) -> list[ProtoTag]:
        """
        Parse AbuseIPDB blocklist data into a dict keyed by validated IP address.

        Args:
            blocklist_data: Raw blocklist data from AbuseIPDB API.

        Returns:
            List of IP addresses with abuse confidence score.
        """
        result = []

        for entry in raw_data:
            ip_addr = entry.get("ipAddress")
            if not ip_addr:
                continue

            is_valid, validated_ip = is_valid_ipv4(ip_addr)
            if not is_valid:
                continue

            tag = ProtoTag(
                    ip=validated_ip,
                    key="confidence_of_abuse",
                    value=entry.get("abuseConfidenceScore")
                )

            result.append(tag)

        return result
