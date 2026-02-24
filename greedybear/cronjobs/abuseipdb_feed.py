import requests
from django.conf import settings

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.extraction.utils import is_valid_ipv4
from greedybear.cronjobs.repositories.tag import TagRepository
from greedybear.models import IOC

SOURCE_NAME = "abuseipdb"


class AbuseIPDBCron(Cronjob):
    """
    Fetch AbuseIPDB blacklist and directly enrich matching IOCs with tags.

    Downloads the AbuseIPDB blacklist (top 10k malicious IPs), joins them
    directly against the IOC table, and writes Tag entries for any matches.
    All existing AbuseIPDB tags are replaced on each run to ensure data freshness.
    """

    MAX_ENTRIES = 10000  # Hard limit as per free API tier

    def __init__(self, tag_repo=None):
        """
        Initialize the AbuseIPDB cronjob.

        Args:
            tag_repo: Optional TagRepository instance for testing.
        """
        super().__init__()
        self.tag_repo = tag_repo if tag_repo is not None else TagRepository()

    def run(self) -> None:
        """
        Fetch AbuseIPDB blacklist, match against our IOC table, and create tags.

        1. Download the blacklist from AbuseIPDB /blacklist endpoint
        2. Validate IP addresses
        3. Query our IOC table for matching IPs (WHERE name IN ...)
        4. Replace all AbuseIPDB tags with fresh data
        """
        api_key = settings.ABUSEIPDB_API_KEY

        if not api_key:
            self.log.warning("AbuseIPDB API key not configured. Skipping enrichment.")
            return

        try:
            self.log.info("Starting AbuseIPDB blacklist download for enrichment")

            # Fetch blacklist from AbuseIPDB
            url = "https://api.abuseipdb.com/api/v2/blacklist"
            headers = {"Key": api_key, "Accept": "application/json"}
            params = {
                "confidenceMinimum": 75,  # Only IPs with confidence >= 75%
                "limit": self.MAX_ENTRIES,  # Maximum 10k entries
            }

            response = requests.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()

            json_data = response.json()
            blacklist_data = json_data.get("data", [])

            self.log.info(f"Retrieved {len(blacklist_data)} IPs from AbuseIPDB blacklist")

            # Parse feed into a dict keyed by IP
            feed_by_ip = self._parse_feed(blacklist_data)
            self.log.info(f"Parsed {len(feed_by_ip)} valid IPs from AbuseIPDB feed")

            if not feed_by_ip:
                # No valid IPs found — clear stale tags and return
                self.tag_repo.replace_tags_for_source(SOURCE_NAME, [])
                return

            # Join against IOC table: find IOCs whose name matches feed IPs
            matching_iocs = IOC.objects.filter(name__in=feed_by_ip.keys()).values_list("id", "name")

            # Build tag entries for matching IOCs
            tag_entries = []
            for ioc_id, ioc_name in matching_iocs:
                enrichment = feed_by_ip[ioc_name]

                if enrichment.get("abuse_confidence_score") is not None:
                    tag_entries.append(
                        {
                            "ioc_id": ioc_id,
                            "key": "confidence_of_abuse",
                            "value": f"{enrichment['abuse_confidence_score']}%",
                        }
                    )
                if enrichment.get("country_code"):
                    tag_entries.append(
                        {
                            "ioc_id": ioc_id,
                            "key": "country_code",
                            "value": enrichment["country_code"],
                        }
                    )

            # Replace all AbuseIPDB tags atomically
            created_count = self.tag_repo.replace_tags_for_source(SOURCE_NAME, tag_entries)
            self.log.info(f"AbuseIPDB enrichment completed. Matched {matching_iocs.count()} IOCs, created {created_count} tags.")

        except requests.RequestException as e:
            self.log.error(f"Failed to fetch AbuseIPDB blacklist: {e}")
            raise

    def _parse_feed(self, blacklist_data: list) -> dict[str, dict]:
        """
        Parse AbuseIPDB blacklist data into a dict keyed by validated IP address.

        Args:
            blacklist_data: Raw blacklist data from AbuseIPDB API.

        Returns:
            Dict mapping IP address -> enrichment dict.
        """
        feed_by_ip: dict[str, dict] = {}

        for entry in blacklist_data:
            ip_addr = entry.get("ipAddress")
            if not ip_addr:
                continue

            is_valid, validated_ip = is_valid_ipv4(ip_addr)
            if not is_valid:
                continue

            feed_by_ip[validated_ip] = {
                "abuse_confidence_score": entry.get("abuseConfidenceScore"),
                "country_code": entry.get("countryCode", ""),
            }

        return feed_by_ip
