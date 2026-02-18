import requests
from django.conf import settings

from greedybear.cronjobs.base import Cronjob
from greedybear.cronjobs.extraction.utils import is_valid_ipv4
from greedybear.cronjobs.repositories import AbuseIPDBRepository


class AbuseIPDBCron(Cronjob):
    """
    Fetch and store AbuseIPDB blacklist data locally.

    Downloads the AbuseIPDB blacklist (top 10k malicious IPs) and stores them
    in the database for later enrichment. Enforces a hard limit of 10k entries.
    """

    MAX_ENTRIES = 10000  # Hard limit as per free API tier

    def __init__(self, abuseipdb_repo=None):
        """
        Initialize the AbuseIPDB cronjob.

        Args:
            abuseipdb_repo: Optional AbuseIPDBRepository instance for testing.
        """
        super().__init__()
        self.abuseipdb_repo = abuseipdb_repo if abuseipdb_repo is not None else AbuseIPDBRepository()

    def run(self) -> None:
        """
        Fetch AbuseIPDB blacklist and store it locally.

        Downloads the blacklist using the /blacklist endpoint, validates IPs,
        and stores them in the local database for enrichment. Enforces 10k entry limit.
        """
        api_key = settings.ABUSEIPDB_API_KEY

        if not api_key:
            self.log.warning("AbuseIPDB API key not configured. Skipping download.")
            return

        try:
            self.log.info("Starting AbuseIPDB blacklist download")

            # Clear old entries first
            self._cleanup_old_entries()

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

            added_count = 0
            for entry in blacklist_data:
                ip_address = entry.get("ipAddress")
                abuse_confidence_score = entry.get("abuseConfidenceScore")
                usage_type = entry.get("usageType", "")
                country_code = entry.get("countryCode", "")

                # Validate IP address
                if ip_address:
                    is_valid, validated_ip = is_valid_ipv4(ip_address)
                    if is_valid:
                        # Store in database
                        entry_obj, created = self.abuseipdb_repo.get_or_create(
                            ip_address=validated_ip,
                            abuse_confidence_score=abuse_confidence_score,
                            usage_type=usage_type,
                            country_code=country_code,
                        )

                        if created:
                            added_count += 1
                            self.log.debug(f"Added AbuseIPDB entry: {validated_ip} (confidence: {abuse_confidence_score}%)")

            self.log.info(f"AbuseIPDB blacklist download completed. Added {added_count} new entries.")

            # Enforce the 10k entry limit
            self.abuseipdb_repo.enforce_limit(max_entries=self.MAX_ENTRIES)

            self.log.info(f"Total AbuseIPDB entries in database: {self.abuseipdb_repo.count()}")

        except requests.RequestException as e:
            self.log.error(f"Failed to fetch AbuseIPDB blacklist: {e}")
            raise
        except Exception as e:
            self.log.error(f"Unexpected error in AbuseIPDB blacklist download: {e}")
            raise

    def _cleanup_old_entries(self):
        """Delete AbuseIPDB entries older than 30 days to keep database clean."""
        deleted_count = self.abuseipdb_repo.cleanup_old_entries(days=30)
        if deleted_count > 0:
            self.log.info(f"Cleaned up {deleted_count} old AbuseIPDB entries")
